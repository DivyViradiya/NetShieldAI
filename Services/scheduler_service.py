"""
Scheduler Service
=================
Core orchestrator for scheduled scanning using APScheduler BackgroundScheduler.
Dispatches scans to all 8 scanner modules based on profile configs.
"""

import json
import time
import uuid
import threading
import traceback
from datetime import datetime
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore

from extensions import db
from logger_setup import logger

# Global scheduler instance
_scheduler = None
_app = None


def get_scheduler():
    """Returns the global scheduler instance."""
    return _scheduler


def init_scheduler(app, scheduler_db_uri):
    """
    Initialize and start the APScheduler BackgroundScheduler.
    Called once from run.py in the WERKZEUG_RUN_MAIN process.
    """
    global _scheduler, _app
    _app = app

    jobstores = {
        'default': SQLAlchemyJobStore(url=scheduler_db_uri + ('?timeout=20' if '?' not in scheduler_db_uri else '&timeout=20'))
    }

    _scheduler = BackgroundScheduler(
        jobstores=jobstores,
        job_defaults={
            'coalesce': True,        # Merge missed fires into one
            'max_instances': 1,       # Prevent overlapping runs of same job
            'misfire_grace_time': 3600  # Allow up to 1hr late execution
        },
        timezone='UTC'
    )

    _scheduler.start()
    logger.info("[+] [SCHEDULER] APScheduler started successfully.")

    # Reload persisted jobs
    reload_all_jobs(app)


def shutdown_scheduler():
    """Gracefully shut down the scheduler."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("[*] [SCHEDULER] APScheduler shut down.")


def _build_trigger(job_row):
    """
    Build an APScheduler trigger from a ScheduledScanJob row.
    """
    if job_row.schedule_type == 'once':
        if not job_row.one_shot_at:
            raise ValueError("one_shot_at is required for 'once' schedule type")
        return DateTrigger(run_date=job_row.one_shot_at)

    elif job_row.schedule_type == 'daily':
        return CronTrigger(
            hour=job_row.cron_hour or 0,
            minute=job_row.cron_minute or 0
        )

    elif job_row.schedule_type == 'weekly':
        day_of_week = job_row.cron_day_of_week or 'mon'
        return CronTrigger(
            day_of_week=day_of_week,
            hour=job_row.cron_hour or 0,
            minute=job_row.cron_minute or 0
        )

    elif job_row.schedule_type == 'monthly':
        day = job_row.cron_day_of_month or 1
        return CronTrigger(
            day=day,
            hour=job_row.cron_hour or 0,
            minute=job_row.cron_minute or 0
        )

    elif job_row.schedule_type == 'periodic':
        from apscheduler.triggers.interval import IntervalTrigger
        interval = job_row.interval_minutes or 60
        return IntervalTrigger(minutes=interval)

    elif job_row.schedule_type == 'cron':
        if not job_row.cron_expression:
            raise ValueError("cron_expression is required for 'cron' schedule type")
        return CronTrigger.from_crontab(job_row.cron_expression)

    else:
        raise ValueError(f"Unknown schedule type: {job_row.schedule_type}")


def register_job(job_row):
    """
    Register a ScheduledScanJob with APScheduler.
    Returns the APScheduler job ID.
    """
    global _scheduler
    if not _scheduler:
        logger.error("[!] [SCHEDULER] Cannot register job — scheduler not initialized.")
        return None

    try:
        trigger = _build_trigger(job_row)
        apscheduler_job_id = f"scheduled_scan_{job_row.id}_{uuid.uuid4().hex[:8]}"

        _scheduler.add_job(
            func=_execute_scheduled_scan_wrapper,
            trigger=trigger,
            args=[job_row.id],
            id=apscheduler_job_id,
            name=f"Scan Job #{job_row.id}",
            replace_existing=True
        )

        logger.info(f"[+] [SCHEDULER] Registered job {apscheduler_job_id} (type={job_row.schedule_type})")
        return apscheduler_job_id

    except Exception as e:
        logger.error(f"[!] [SCHEDULER] Failed to register job {job_row.id}: {e}")
        return None


def unregister_job(apscheduler_job_id):
    """Remove a job from APScheduler."""
    global _scheduler
    if not _scheduler:
        return

    try:
        _scheduler.remove_job(apscheduler_job_id)
        logger.info(f"[*] [SCHEDULER] Unregistered job {apscheduler_job_id}")
    except Exception as e:
        logger.warning(f"[!] [SCHEDULER] Could not remove job {apscheduler_job_id}: {e}")


def _execute_scheduled_scan_wrapper(job_id):
    """
    Wrapper that runs the scan inside the Flask app context.
    This is the function APScheduler calls.
    """
    global _app
    if not _app:
        logger.error("[!] [SCHEDULER] No Flask app reference — cannot execute scan.")
        return

    with _app.app_context():
        try:
            _execute_scheduled_scan(job_id)
        except Exception as e:
            logger.error(f"[!] [SCHEDULER] Error executing job {job_id}: {e}")
            traceback.print_exc()


def _execute_scheduled_scan(job_id):
    """
    Core execution logic for a scheduled scan.
    Loads the job → profile → configs → targets, then dispatches each scan.
    """
    from scheduler_models import ScheduledScanJob, ScanProfile, ProfileScanConfig, ProfileTarget
    from models import User
    from extensions import db
    from Services import scan_logger

    # 1. Load the job
    job = db.session.get(ScheduledScanJob, job_id)
    if not job:
        logger.error(f"[!] [SCHEDULER] Job {job_id} not found in DB.")
        return

    if not job.is_enabled:
        logger.info(f"[*] [SCHEDULER] Job {job_id} is disabled — skipping.")
        return

    # 2. Load the profile
    profile = db.session.get(ScanProfile, job.profile_id)
    if not profile or not profile.is_active:
        logger.warning(f"[!] [SCHEDULER] Profile {job.profile_id} not found or inactive — skipping job {job_id}.")
        return

    # 3. Verify user exists in primary DB
    user = db.session.get(User, profile.user_id)
    if not user:
        logger.error(f"[!] [SCHEDULER] User {profile.user_id} not found — skipping job {job_id}.")
        return

    # 4. Load configs and targets
    configs = ProfileScanConfig.query.filter_by(profile_id=profile.id).all()
    targets = ProfileTarget.query.filter_by(profile_id=profile.id).all()

    if not configs:
        logger.warning(f"[!] [SCHEDULER] Profile '{profile.name}' has no scan configs — skipping.")
        return

    if not targets:
        logger.warning(f"[!] [SCHEDULER] Profile '{profile.name}' has no targets — skipping.")
        return

    logger.info(f"[*] [SCHEDULER] Executing job {job_id}: Profile '{profile.name}' "
                f"({len(configs)} configs × {len(targets)} targets)")

    # Build user identifier (must match the pattern used across all blueprints)
    from werkzeug.utils import secure_filename
    user_identifier = f"{secure_filename(user.username)}_{user.id}"

    import os
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # 5. Dispatch each target × config combination
    for target_row in targets:
        target = target_row.target_url
        for config_row in configs:
            module = config_row.module
            config = json.loads(config_row.config_json) if config_row.config_json else {}

            logger.info(f"[*] [SCHEDULER] Dispatching {module} scan on {target} "
                        f"(config: {config_row.display_label or module})")

            try:
                _dispatch_module_scan(
                    module=module,
                    target=target,
                    config=config,
                    user=user,
                    user_identifier=user_identifier,
                    base_dir=base_dir
                )
            except Exception as e:
                logger.error(f"[!] [SCHEDULER] Error dispatching {module} scan on {target}: {e}")
                traceback.print_exc()

    # 6. Update job metadata
    job.last_run_at = datetime.utcnow()

    # Compute next run for non-one-shot jobs
    if job.schedule_type != 'once' and _scheduler:
        try:
            aps_job = _scheduler.get_job(job.apscheduler_job_id)
            if aps_job and aps_job.next_run_time:
                job.next_run_at = aps_job.next_run_time.replace(tzinfo=None)
        except Exception:
            pass

    # Disable one-shot jobs after execution
    if job.schedule_type == 'once':
        job.is_enabled = False

    db.session.commit()
    logger.info(f"[+] [SCHEDULER] Job {job_id} execution complete.")


def _dispatch_module_scan(module, target, config, user, user_identifier, base_dir):
    """
    Dispatches a scan to the appropriate scanner module.
    Each dispatch runs in a new thread to match the existing concurrency model.
    """
    import os
    from extensions import db as primary_db
    from Services import scan_logger
    from sqlalchemy import update as sa_update
    from models import User as UserModel

    if module == 'nmap':
        _dispatch_nmap(target, config, user, user_identifier, base_dir)

    elif module == 'zap':
        _dispatch_zap(target, config, user, user_identifier, base_dir)

    elif module == 'ssl':
        _dispatch_ssl(target, config, user, user_identifier, base_dir)

    elif module == 'sniffer':
        _dispatch_sniffer(target, config, user, user_identifier, base_dir)

    elif module == 'sql':
        _dispatch_sql(target, config, user, user_identifier, base_dir)

    elif module == 'semgrep':
        _dispatch_semgrep(target, config, user, user_identifier, base_dir)

    elif module == 'api':
        _dispatch_api(target, config, user, user_identifier, base_dir)

    elif module == 'killchain':
        _dispatch_killchain(target, config, user, user_identifier, base_dir)

    else:
        logger.warning(f"[!] [SCHEDULER] Unknown module: {module}")


# ============================================================
# Module-specific dispatchers
# ============================================================

def _dispatch_nmap(target, config, user, user_identifier, base_dir):
    """Dispatch an Nmap scan."""
    import os
    from Services import network_scanner, scan_logger, pdf_generator
    from extensions import db as primary_db
    from sqlalchemy import update as sa_update
    from models import User as UserModel

    scan_type = config.get('scan_type', 'default')
    protocol_type = config.get('protocol_type', 'TCP')
    timing = config.get('timing', 4)

    user_dir = os.path.join(base_dir, 'results', user_identifier, 'network_scanner')
    os.makedirs(user_dir, exist_ok=True)

    # Increment counter
    primary_db.session.execute(
        sa_update(UserModel).where(UserModel.id == user.id)
        .values(scan_count_nmap=UserModel.scan_count_nmap + 1)
    )
    primary_db.session.commit()

    scan_logger.reset_log_file(user_identifier, "network_scanner")
    log_id = scan_logger.log_scan_start(user.id, "Nmap", target, scan_type=scan_type)

    start_time = time.time()
    queue_id = str(uuid.uuid4())

    result_file = network_scanner.run_nmap_scan(
        target, protocol_type=protocol_type, scan_type=scan_type,
        output_dir=user_dir, user_id=user_identifier, timing=timing, queue_id=queue_id
    )

    duration = time.time() - start_time
    status = "Completed" if result_file else "Failed"
    finding_count = len(network_scanner.get_current_open_ports(user_identifier)) if result_file else 0

    scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration)

    if result_file:
        try:
            user_paths = network_scanner.get_output_paths(user_dir, target=target)
            if os.path.exists(user_paths["json_report"]):
                pdf_generator.create_nmap_report_pdf(str(user_paths["json_report"]), str(user_paths["pdf_report"]))
        except Exception as e:
            logger.error(f"[!] [SCHEDULER] Nmap PDF generation failed: {e}")

    logger.info(f"[+] [SCHEDULER] Nmap scan on {target} finished: {status}")


def _dispatch_zap(target, config, user, user_identifier, base_dir):
    """Dispatch a ZAP scan."""
    import os
    from Services import zap_scanner, scan_logger, pdf_generator, report_manager
    from extensions import db as primary_db
    from sqlalchemy import update as sa_update
    from models import User as UserModel

    scan_mode = config.get('scan_mode', 'default')

    user_dir = os.path.join(base_dir, 'results', user_identifier, 'zap_scanner')
    os.makedirs(user_dir, exist_ok=True)

    # Ensure target has protocol
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    primary_db.session.execute(
        sa_update(UserModel).where(UserModel.id == user.id)
        .values(scan_count_zap=UserModel.scan_count_zap + 1)
    )
    primary_db.session.commit()

    paths = zap_scanner.get_output_paths(user_dir, target=target)
    xml_path = paths["xml_report"]
    pdf_path = paths["pdf_report"]
    os.makedirs(os.path.dirname(str(xml_path)), exist_ok=True)

    start_time = time.time()
    scan_successful = zap_scanner.run_zap_scan(target, str(xml_path), user_identifier, scan_mode=scan_mode)
    duration = time.time() - start_time

    finding_count = 0
    status = "Failed"

    if scan_successful:
        status = "Completed"
        scan_results = zap_scanner.parse_zap_xml_report(str(xml_path), user_identifier)
        if scan_results:
            scan_results["target_url"] = target
            finding_count = len(scan_results.get("findings", []))
            json_path = zap_scanner.save_json_report(scan_results, user_dir, user_identifier, target=target)
            if json_path:
                try:
                    pdf_generator.create_zap_report_pdf(json_path, str(pdf_path))
                except Exception as e:
                    logger.error(f"[!] [SCHEDULER] ZAP PDF generation failed: {e}")

    scan_logger.create_full_scan_log(user.id, "ZAP", target, duration, finding_count, status=status)
    logger.info(f"[+] [SCHEDULER] ZAP scan on {target} finished: {status}")


def _dispatch_ssl(target, config, user, user_identifier, base_dir):
    """Dispatch an SSL scan."""
    import os
    from Services import ssl_scanner, scan_logger, pdf_generator
    from extensions import db as primary_db
    from sqlalchemy import update as sa_update
    from models import User as UserModel

    user_dir = os.path.join(base_dir, 'results', user_identifier, 'ssl_scanner')
    os.makedirs(user_dir, exist_ok=True)

    primary_db.session.execute(
        sa_update(UserModel).where(UserModel.id == user.id)
        .values(scan_count_ssl=UserModel.scan_count_ssl + 1)
    )
    primary_db.session.commit()

    scan_logger.reset_log_file(user_identifier, "ssl_scanner")
    log_id = scan_logger.log_scan_start(user.id, "SSLScan", target, scan_type="Standard")

    start_time = time.time()
    report_file = ssl_scanner.run_ssl_scan(target, output_dir=user_dir, user_id=user_identifier)
    duration = time.time() - start_time

    status = "Failed"
    finding_count = 0

    if report_file:
        status = "Completed"
        summary = ssl_scanner.parse_ssl_report(report_file, output_dir=user_dir, user_id=user_identifier, target=target)
        if summary:
            finding_count = len(summary.get('protocols', [])) + len(summary.get('vulnerabilities', []))
            try:
                user_paths = ssl_scanner.get_output_paths(user_dir, target=target)
                pdf_generator.create_ssl_report_pdf(str(user_paths["json_report"]), str(user_paths["pdf_report"]))
            except Exception as e:
                logger.error(f"[!] [SCHEDULER] SSL PDF generation failed: {e}")

    scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration)
    logger.info(f"[+] [SCHEDULER] SSL scan on {target} finished: {status}")


def _dispatch_sniffer(target, config, user, user_identifier, base_dir):
    """Dispatch a packet sniffer capture."""
    import os
    from extensions import db as primary_db
    from sqlalchemy import update as sa_update
    from models import User as UserModel
    from Services import packet_sniffer, scan_logger, pdf_generator

    duration_sec = config.get('duration', 60)
    interface = config.get('interface', None)

    user_dir = os.path.join(base_dir, 'results', user_identifier, 'packet_sniffer')
    os.makedirs(user_dir, exist_ok=True)

    primary_db.session.execute(
        sa_update(UserModel).where(UserModel.id == user.id)
        .values(scan_count_sniffer=UserModel.scan_count_sniffer + 1)
    )
    primary_db.session.commit()

    scan_logger.reset_log_file(user_identifier, "packet_sniffer")
    log_id = scan_logger.log_scan_start(user.id, "Sniffer", target, scan_type="Scheduled")

    start_time = time.time()
    # run_packet_capture handles its own pcap saving
    sniffer_results = packet_sniffer.run_packet_capture(
        target_ip=target,
        duration=duration_sec,
        interface=interface,
        user_id=user_identifier
    )
    duration = time.time() - start_time

    status = "Completed" if sniffer_results else "Failed"
    finding_count = len(sniffer_results.get("security_anomaly_report", {}).get("port_scans", [])) if sniffer_results else 0

    scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration)

    if sniffer_results:
        try:
            # packet_sniffer saves to a fixed place in results/
            # We need to find where it saved and generate PDF
            json_report = os.path.join(base_dir, 'results', user_identifier, 'packet_sniffer', f"sniffer_report_{target.replace('.','_')}.json")
            pdf_report = json_report.replace('.json', '.pdf')
            if os.path.exists(json_report):
                pdf_generator.create_packet_sniffer_report_pdf(json_report, pdf_report)
        except Exception as e:
            logger.error(f"[!] [SCHEDULER] Sniffer PDF generation failed: {e}")

    logger.info(f"[+] [SCHEDULER] Sniffer scheduled capture for {target} finished: {status}")


def _dispatch_sql(target, config, user, user_identifier, base_dir):
    """Dispatch a SQL injection scan."""
    import os
    from extensions import db as primary_db
    from sqlalchemy import update as sa_update
    from models import User as UserModel
    from Services import sql_scanner, scan_logger, pdf_generator

    scan_type = config.get('scan_type', 'standard')
    user_dir = os.path.join(base_dir, 'results', user_identifier, 'sql_scanner')
    os.makedirs(user_dir, exist_ok=True)

    primary_db.session.execute(
        sa_update(UserModel).where(UserModel.id == user.id)
        .values(scan_count_sql=UserModel.scan_count_sql + 1)
    )
    primary_db.session.commit()

    scan_logger.reset_log_file(user_identifier, "sql_scanner")
    log_id = scan_logger.log_scan_start(user.id, "SQLMap", target, scan_type=scan_type)

    start_time = time.time()
    # Ensure target has protocol
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    sql_results = sql_scanner.run_sql_scan(target, scan_type=scan_type, user_id=user_identifier)
    duration = time.time() - start_time

    status = "Completed" if sql_results else "Failed"
    finding_count = len(sql_results.get("vulnerabilities", [])) if sql_results else 0

    scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration)

    if sql_results:
        try:
            json_path = os.path.join(user_dir, f"sql_report_{target.replace('://','_').replace('/','_').replace('.','_')}.json")
            pdf_path = json_path.replace('.json', '.pdf')
            if os.path.exists(json_path):
                pdf_generator.create_sql_report_pdf(json_path, pdf_path)
        except Exception as e:
            logger.error(f"[!] [SCHEDULER] SQL PDF generation failed: {e}")

    logger.info(f"[+] [SCHEDULER] SQL scan on {target} finished: {status}")


def _dispatch_semgrep(target, config, user, user_identifier, base_dir):
    """Dispatch a Semgrep SAST scan."""
    import os
    from extensions import db as primary_db
    from sqlalchemy import update as sa_update
    from models import User as UserModel
    from Services import semgrep_scanner, scan_logger, pdf_generator

    ruleset = config.get('ruleset', 'auto')
    user_dir = os.path.join(base_dir, 'results', user_identifier, 'semgrep_scanner')
    os.makedirs(user_dir, exist_ok=True)

    primary_db.session.execute(
        sa_update(UserModel).where(UserModel.id == user.id)
        .values(scan_count_semgrep=UserModel.scan_count_semgrep + 1)
    )
    primary_db.session.commit()

    scan_logger.reset_log_file(user_identifier, "semgrep_scanner")
    log_id = scan_logger.log_scan_start(user.id, "Semgrep", target, scan_type=ruleset)

    start_time = time.time()
    # Semgrep scans local paths or repositories
    semgrep_results = semgrep_scanner.run_semgrep_scan(target, ruleset=ruleset, user_id=user_identifier)
    duration = time.time() - start_time

    status = "Completed" if semgrep_results else "Failed"
    finding_count = len(semgrep_results.get("findings", [])) if semgrep_results else 0

    scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration)

    if semgrep_results:
        try:
            # We need to find where it saved and generate PDF
            json_report = os.path.join(user_dir, f"semgrep_report_{os.path.basename(target).replace('.','_')}.json")
            pdf_report = json_report.replace('.json', '.pdf')
            if os.path.exists(json_report):
                pdf_generator.create_semgrep_report_pdf(json_report, pdf_report)
        except Exception as e:
            logger.error(f"[!] [SCHEDULER] Semgrep PDF generation failed: {e}")

    logger.info(f"[+] [SCHEDULER] Semgrep scan on {target} finished: {status}")


def _dispatch_api(target, config, user, user_identifier, base_dir):
    """Dispatch an API scan."""
    import os
    from extensions import db as primary_db
    from sqlalchemy import update as sa_update
    from models import User as UserModel
    from Services import api_scanner, scan_logger, pdf_generator

    scan_mode = config.get('scan_mode', 'quick')
    user_dir = os.path.join(base_dir, 'results', user_identifier, 'api_scanner')
    os.makedirs(user_dir, exist_ok=True)

    primary_db.session.execute(
        sa_update(UserModel).where(UserModel.id == user.id)
        .values(scan_count_api=UserModel.scan_count_api + 1)
    )
    primary_db.session.commit()

    scan_logger.reset_log_file(user_identifier, "api_scanner")
    log_id = scan_logger.log_scan_start(user.id, "API Scanner", target, scan_type=scan_mode)

    start_time = time.time()
    # API scan requires ZAP daemon usually handled inside run_api_scan
    api_results = api_scanner.run_api_scan(target, scan_mode=scan_mode, user_id=user_identifier)
    duration = time.time() - start_time

    status = "Completed" if api_results else "Failed"
    finding_count = len(api_results.get("findings", [])) if api_results else 0

    scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration)

    if api_results:
        try:
            # We need to find where it saved and generate PDF
            # api_scanner might save as zap_api_report...
            json_report = os.path.join(user_dir, f"api_report_{target.replace('://','_').replace('/','_').replace('.','_')}.json")
            pdf_report = json_report.replace('.json', '.pdf')
            # Wait, api_scanner returns the data. We should save it first or call pdf_generator directly if it takes dict
            # Most create_..._pdf take source_data which can be a dict. Let's check api_scanner saves JSON too?
            # Looking at api_scanner.py, it seems it doesn't automatically save JSON.
            # Let's save it here for consistency.
            with open(json_report, 'w') as f:
                json.dump(api_results, f)
            pdf_generator.create_zap_report_pdf(api_results, pdf_report) # reusing ZAP template as API scan is ZAP based
        except Exception as e:
            logger.error(f"[!] [SCHEDULER] API PDF generation failed: {e}")

    logger.info(f"[+] [SCHEDULER] API scan on {target} finished: {status}")


def _dispatch_killchain(target, config, user, user_identifier, base_dir):
    """Dispatch a Kill Chain audit — fully integrated."""
    import os
    from Services.killchain_service import killchain_service
    from Services import scan_logger
    from extensions import db as primary_db

    profile_name = config.get('profile', 'Full Scan')
    aggression = config.get('aggression', 'Normal')

    user_dir = os.path.join(base_dir, 'results', user_identifier, 'killchain')
    os.makedirs(user_dir, exist_ok=True)

    # Increment counter
    user.scan_count_killchain += 1
    primary_db.session.commit()

    scan_logger.reset_log_file(user_identifier, "killchain")
    log_id = scan_logger.log_scan_start(user.id, "Kill Chain", target, scan_type=f"{profile_name} ({aggression})")

    scan_id = str(uuid.uuid4())[:8]
    queue_id = f"{user_identifier}::{scan_id}"

    # Run synchronously within the scheduler thread (already in a background thread)
    killchain_service.run_job(
        target=target,
        profile_name=profile_name,
        aggression_level=aggression,
        queue_id=queue_id,
        user_output_dir=user_dir,
        log_id=log_id,
        app=_app
    )

    logger.info(f"[+] [SCHEDULER] Kill Chain audit on {target} completed.")


def reload_all_jobs(app):
    """
    On startup, re-register all enabled ScheduledScanJob rows.
    Ensures jobs survive server restarts.
    """
    with app.app_context():
        try:
            from scheduler_models import ScheduledScanJob
            enabled_jobs = ScheduledScanJob.query.filter_by(is_enabled=True).all()

            if not enabled_jobs:
                logger.info("[*] [SCHEDULER] No enabled jobs found to reload.")
                return

            for job_row in enabled_jobs:
                aps_id = register_job(job_row)
                if aps_id and aps_id != job_row.apscheduler_job_id:
                    # Update stored reference
                    job_row.apscheduler_job_id = aps_id

                    # Update next_run_at
                    try:
                        aps_job = _scheduler.get_job(aps_id)
                        if aps_job and aps_job.next_run_time:
                            job_row.next_run_at = aps_job.next_run_time.replace(tzinfo=None)
                    except Exception:
                        pass

            db.session.commit()
            logger.info(f"[+] [SCHEDULER] Reloaded {len(enabled_jobs)} scheduled jobs.")

        except Exception as e:
            logger.error(f"[!] [SCHEDULER] Failed to reload jobs: {e}")
            traceback.print_exc()
