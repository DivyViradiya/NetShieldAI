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
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
IST = ZoneInfo("Asia/Kolkata")
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore

from core.extensions import db
from core.logger_setup import logger
from flask import render_template, url_for
import secrets
from Services.email_service import send_consent_email

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

    # Silence verbose APScheduler heartbeat/execution logs in console
    import logging
    logging.getLogger('apscheduler').setLevel(logging.WARNING)

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
        timezone=IST
    )

    _scheduler.start()
    logger.info("[+] [SCHEDULER] APScheduler started successfully.")

    # Start consent watchdog (runs every minute)
    _scheduler.add_job(
        func=_consent_watchdog,
        trigger='interval',
        minutes=1,
        id='consent_watchdog',
        name='Consent Notification Watchdog',
        replace_existing=True
    )
    logger.info("[+] [SCHEDULER] Consent watchdog started.")

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
        run_date = job_row.one_shot_at
        if run_date.tzinfo is None:
            run_date = run_date.replace(tzinfo=IST)
        return DateTrigger(run_date=run_date, timezone=IST)

    elif job_row.schedule_type == 'daily':
        return CronTrigger(
            hour=job_row.cron_hour or 0,
            minute=job_row.cron_minute or 0,
            timezone=IST
        )

    elif job_row.schedule_type == 'weekly':
        day_of_week = job_row.cron_day_of_week or 'mon'
        return CronTrigger(
            day_of_week=day_of_week,
            hour=job_row.cron_hour or 0,
            minute=job_row.cron_minute or 0,
            timezone=IST
        )

    elif job_row.schedule_type == 'monthly':
        day = job_row.cron_day_of_month or '1'
        return CronTrigger(
            day=day,
            hour=job_row.cron_hour or 0,
            minute=job_row.cron_minute or 0,
            timezone=IST
        )

    elif job_row.schedule_type == 'periodic':
        from apscheduler.triggers.interval import IntervalTrigger
        interval = job_row.interval_minutes or 60
        return IntervalTrigger(minutes=interval, timezone=IST)

    elif job_row.schedule_type == 'cron':
        if not job_row.cron_expression:
            raise ValueError("cron_expression is required for 'cron' schedule type")
        return CronTrigger.from_crontab(job_row.cron_expression, timezone=IST)

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
        # Use a DETERMINISTIC ID so replace_existing=True actually replaces the old job.
        # Previously, a UUID suffix was appended, causing orphaned jobs to accumulate.
        apscheduler_job_id = f"scheduled_scan_{job_row.id}"

        _scheduler.add_job(
            func=_execute_scheduled_scan_wrapper,
            trigger=trigger,
            args=[job_row.id],
            id=apscheduler_job_id,
            name=f"Scan Job #{job_row.id}",
            replace_existing=True
        )

        # Update next_run_at in DB
        try:
            aps_job = _scheduler.get_job(apscheduler_job_id)
            if aps_job and aps_job.next_run_time:
                job_row.next_run_at = aps_job.next_run_time.replace(tzinfo=None)
                db.session.commit()
        except Exception:
            pass

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


def _execute_scheduled_scan_wrapper(job_id, force_run=False):
    """
    Wrapper that runs the scan inside the Flask app context.
    This is the function APScheduler calls.
    """
    global _app
    if not _app:
        logger.error("[!] [SCHEDULER] No Flask app reference — cannot execute scan.")
        return

    base_url = _app.config.get('BASE_URL', 'http://localhost:5100')
    with _app.test_request_context(base_url=base_url):
        try:
            _execute_scheduled_scan(job_id, force_run=force_run)
        except Exception as e:
            logger.error(f"[!] [SCHEDULER] Error executing job {job_id}: {e}")
            traceback.print_exc()


def _check_scan_consent(job, target_row, profile, user):
    """
    Checks if consent exists for a scan.
    Returns: True if consent granted, False if deferred.
    """
    from models.scheduler_models import ScanConsentToken
    
    # Run Once does not require consent
    if job.schedule_type == 'once':
        return True

    logger.info(f"[*] [SCHEDULER] Checking consent for Job {job.id}, Target {target_row.id}")
    # 1. Check for valid existing approved consent
    existing = ScanConsentToken.query.filter_by(
        job_id=job.id, 
        target_id=target_row.id, 
        status='approved'
    ).first()

    if existing:
        logger.info(f"[+] [SCHEDULER] Consent already approved for Job {job.id}")
        return True

    # 2. Check for pending request (within expiry)
    pending = ScanConsentToken.query.filter_by(
        job_id=job.id, 
        target_id=target_row.id, 
        status='pending'
    ).order_by(ScanConsentToken.created_at.desc()).first()

    if pending and not pending.is_expired():
        logger.info(f"[*] [SCHEDULER] Pending consent already exists for Job {job.id}")
        return False

    # 3. If no approved/pending exists, and it's execution time, 
    # the watchdog should have sent it. If it didn't (e.g. worker down),
    # we trigger it now and defer.
    logger.warning(f"[!] [SCHEDULER] No consent found at execution time for Job {job.id} — triggering emergency request.")
    _trigger_consent_request(job, target_row, profile)
    return False


def _trigger_consent_request(job, target_row, profile):
    """Creates a token and sends the consent email."""
    from models.scheduler_models import ScanConsentToken
    from core.extensions import db
    import datetime as dt

    # Check if *any* token for this job/target was created recently to avoid spam.
    # This covers: pending (not yet clicked), approved (just used), expired (scan just ran).
    all_recent = ScanConsentToken.query.filter_by(
        job_id=job.id,
        target_id=target_row.id,
    ).all()
    
    now_naive = datetime.now(IST).replace(tzinfo=None)
    for p in all_recent:
        diff = now_naive - p.created_at
        # Don't send another email if one was sent in the last 45 minutes
        if diff.total_seconds() < 45 * 60:
            logger.info(f"[*] [SCHEDULER] Skipping email for Job {job.id} — last request [{p.status}] sent {diff.total_seconds()/60:.1f}m ago.")
            return

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(IST).replace(tzinfo=None) + dt.timedelta(hours=1)
    
    new_token = ScanConsentToken(
        job_id=job.id,
        target_id=target_row.id,
        token=token,
        expires_at=expires_at,
        status='pending'
    )
    db.session.add(new_token)
    db.session.commit()

    logger.info(f"[*] [SCHEDULER] Sending consent email to {target_row.consent_email} for {target_row.target_url}")
    base_url = _app.config.get('BASE_URL', 'http://localhost:5100')
    with _app.test_request_context(base_url=base_url):
        confirm_url = url_for('scheduler_bp.confirm_scan', token=token, _external=True)

        # Build richer scan context for the email
        from models.scheduler_models import ProfileScanConfig
        configs = ProfileScanConfig.query.filter_by(profile_id=job.profile_id).all()
        tools_list = [c.display_label or c.module.upper() for c in configs]
        schedule_type_label = {
            'periodic': 'Recurring (Periodic)',
            'daily': 'Daily',
            'weekly': 'Weekly',
            'monthly': 'Monthly',
            'cron': 'Advanced (Cron)',
        }.get(job.schedule_type, job.schedule_type.capitalize())
        scheduled_time = job.next_run_at.strftime('%d %b %Y at %H:%M IST') if job.next_run_at else 'As Scheduled'

        html_content = render_template(
            'email/scan_consent.html',
            target_url=target_row.target_url,
            profile_name=profile.name,
            confirm_url=confirm_url,
            tools_list=tools_list,
            schedule_type=schedule_type_label,
            scheduled_time=scheduled_time,
            current_year=datetime.now(IST).year
        )
        # Use the actual NS logo for inline embedding
        logo_path = Path(_app.root_path) / 'static' / 'images' / 'NS_Logo.png'
        
        success = send_consent_email(
            recipient_email=target_row.consent_email,
            target_url=target_row.target_url,
            profile_name=profile.name,
            confirm_url=confirm_url,
            html_content=html_content,
            logo_path=str(logo_path) if logo_path.exists() else None
        )
        if success:
            logger.info(f"[+] [SCHEDULER] Consent email sent successfully to {target_row.consent_email}")
        else:
            logger.error(f"[!] [SCHEDULER] Failed to send consent email to {target_row.consent_email}")

    return success


def _execute_scheduled_scan(job_id, force_run=False):
    """
    Core execution logic for a scheduled scan.
    Loads the job → profile → configs → targets, then dispatches each scan.
    """
    from models.scheduler_models import ScheduledScanJob, ScanProfile, ProfileScanConfig, ProfileTarget
    from models.models import User
    from core.extensions import db
    from Services import scan_logger

    # 1. Load the job
    job = db.session.get(ScheduledScanJob, job_id)
    if not job:
        logger.error(f"[!] [SCHEDULER] Job {job_id} not found in DB.")
        return

    if not job.is_enabled and not force_run:
        logger.info(f"[*] [SCHEDULER] Job {job_id} is disabled and not forced — skipping.")
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
    
    # NEW: Generate a single timestamp for the entire job run to group findings
    from Services import report_manager
    shared_timestamp = report_manager.get_timestamp()

    # 5. Dispatch each target × config combination
    for target_row in targets:
        target = target_row.target_url
        
        # --- [GOVERNANCE & CONSENT CHECK] ---
        if target_row.requires_consent:
            consent_granted = _check_scan_consent(job, target_row, profile, user)
            if not consent_granted:
                logger.info(f"[*] [SCHEDULER] Scan deferred for {target} — awaiting consent from {target_row.consent_email}")
                continue
            else:
                # IMPORTANT: Invalidate the token after it has been used once.
                # This ensures the user is asked for consent again for the next recurring cycle.
                from models.scheduler_models import ScanConsentToken
                used_token = ScanConsentToken.query.filter_by(
                    job_id=job.id, 
                    target_id=target_row.id, 
                    status='approved'
                ).first()
                if used_token:
                    used_token.status = 'expired'
                    db.session.commit()
                    logger.info(f"[+] [SCHEDULER] Consent token for {target} marked as used/expired.")
        # ------------------------------------

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
                    base_dir=base_dir,
                    timestamp=shared_timestamp
                )
            except Exception as e:
                logger.error(f"[!] [SCHEDULER] Error dispatching {module} scan on {target}: {e}")
                traceback.print_exc()

    # 6. Update job metadata
    job.last_run_at = datetime.now(IST).replace(tzinfo=None)

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


def _dispatch_module_scan(module, target, config, user, user_identifier, base_dir, timestamp=None):
    """
    Dispatches a scan to the appropriate scanner module.
    Each dispatch runs in a new thread to match the existing concurrency model.
    """
    import os
    from core.extensions import db as primary_db
    from Services import scan_logger
    from sqlalchemy import update as sa_update
    from models.models import User as UserModel

    if module == 'nmap':
        _dispatch_nmap(target, config, user, user_identifier, base_dir, timestamp=timestamp)

    elif module == 'zap':
        _dispatch_zap(target, config, user, user_identifier, base_dir, timestamp=timestamp)

    elif module == 'ssl':
        _dispatch_ssl(target, config, user, user_identifier, base_dir, timestamp=timestamp)

    elif module == 'sniffer':
        _dispatch_sniffer(target, config, user, user_identifier, base_dir, timestamp=timestamp)

    elif module == 'sql':
        _dispatch_sql(target, config, user, user_identifier, base_dir, timestamp=timestamp)

    elif module == 'semgrep':
        _dispatch_semgrep(target, config, user, user_identifier, base_dir, timestamp=timestamp)

    elif module == 'api':
        _dispatch_api(target, config, user, user_identifier, base_dir, timestamp=timestamp)

    elif module == 'killchain':
        _dispatch_killchain(target, config, user, user_identifier, base_dir, timestamp=timestamp)

    else:
        logger.warning(f"[!] [SCHEDULER] Unknown module: {module}")


# ============================================================
# Module-specific dispatchers
# ============================================================

def _dispatch_nmap(target, config, user, user_identifier, base_dir, timestamp=None):
    """Dispatch an Nmap scan."""
    import os
    from Services import network_scanner, scan_logger, pdf_generator
    from core.extensions import db as primary_db
    from sqlalchemy import update as sa_update
    from models.models import User as UserModel

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
    log_id = scan_logger.log_scan_start(user.id, "Nmap", target, scan_type=scan_type, origin="scheduled")

    start_time = time.time()
    queue_id = str(uuid.uuid4())

    # IMPORTANT: network_scanner.run_nmap_scan needs to use the same timestamp for its output files.
    # We pass it to get_output_paths inside run_nmap_scan if we could, 
    # but here we use it to calculate the paths for the logger and PDF generation.
    user_paths = network_scanner.get_output_paths(user_dir, target=target, timestamp=timestamp)

    result_file = network_scanner.run_nmap_scan(
        target, protocol_type=protocol_type, scan_type=scan_type,
        output_dir=user_dir, user_id=user_identifier, timing=timing, queue_id=queue_id,
        timestamp=timestamp # Pass timestamp down
    )

    duration = time.time() - start_time
    status = "Completed" if result_file else "Failed"
    finding_count = len(network_scanner.get_current_open_ports(user_identifier)) if result_file else 0

    scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration, report_path=str(user_paths["pdf_report"]) if result_file else None)

    if result_file:
        try:
            if os.path.exists(user_paths["json_report"]):
                pdf_generator.create_nmap_report_pdf(str(user_paths["json_report"]), str(user_paths["pdf_report"]))
        except Exception as e:
            logger.error(f"[!] [SCHEDULER] Nmap PDF generation failed: {e}")

    logger.info(f"[+] [SCHEDULER] Nmap scan on {target} finished: {status}")


def _dispatch_zap(target, config, user, user_identifier, base_dir, timestamp=None):
    """Dispatch a ZAP scan."""
    import os
    from Services import zap_scanner, scan_logger, pdf_generator, report_manager
    from core.extensions import db as primary_db
    from sqlalchemy import update as sa_update
    from models.models import User as UserModel

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

    paths = zap_scanner.get_output_paths(user_dir, target=target, timestamp=timestamp)
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
            json_path = zap_scanner.save_json_report(scan_results, user_dir, user_identifier, target=target, timestamp=timestamp)
            if json_path:
                try:
                    pdf_generator.create_zap_report_pdf(json_path, str(pdf_path))
                except Exception as e:
                    logger.error(f"[!] [SCHEDULER] ZAP PDF generation failed: {e}")

    scan_logger.create_full_scan_log(user.id, "ZAP", target, duration, finding_count, status=status, report_path=str(pdf_path) if scan_successful else None, origin="scheduled")
    logger.info(f"[+] [SCHEDULER] ZAP scan on {target} finished: {status}")


def _dispatch_ssl(target, config, user, user_identifier, base_dir, timestamp=None):
    """Dispatch an SSL scan."""
    import os
    from Services import ssl_scanner, scan_logger, pdf_generator
    from core.extensions import db as primary_db
    from sqlalchemy import update as sa_update
    from models.models import User as UserModel

    user_dir = os.path.join(base_dir, 'results', user_identifier, 'ssl_scanner')
    os.makedirs(user_dir, exist_ok=True)

    primary_db.session.execute(
        sa_update(UserModel).where(UserModel.id == user.id)
        .values(scan_count_ssl=UserModel.scan_count_ssl + 1)
    )
    primary_db.session.commit()

    scan_logger.reset_log_file(user_identifier, "ssl_scanner")
    log_id = scan_logger.log_scan_start(user.id, "SSLScan", target, scan_type="Standard", origin="scheduled")

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
    
    user_paths = ssl_scanner.get_output_paths(user_dir, target=target, timestamp=timestamp)
    scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration, report_path=str(user_paths["pdf_report"]) if report_file else None)

    if report_file:
        try:
            pdf_generator.create_ssl_report_pdf(str(user_paths["json_report"]), str(user_paths["pdf_report"]))
        except Exception as e:
            logger.error(f"[!] [SCHEDULER] SSL PDF generation failed: {e}")

    logger.info(f"[+] [SCHEDULER] SSL scan on {target} finished: {status}")


def _dispatch_sniffer(target, config, user, user_identifier, base_dir, timestamp=None):
    """Dispatch a packet sniffer capture."""
    import os
    from core.extensions import db as primary_db
    from sqlalchemy import update as sa_update
    from models.models import User as UserModel
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
    log_id = scan_logger.log_scan_start(user.id, "Sniffer", target, scan_type="Scheduled", origin="scheduled")

    start_time = time.time()
    # run_packet_capture handles its own pcap saving
    sniffer_results = packet_sniffer.run_packet_capture(
        target_ip=target,
        duration_seconds=duration_sec,
        interface_id=interface,
        user_id=user_identifier
    )
    duration = time.time() - start_time

    status = "Completed" if sniffer_results else "Failed"
    
    # Use the same output path helper as the sniffer logic
    user_paths = packet_sniffer.get_output_paths(user_dir, user_id=user_identifier, target=target, timestamp=timestamp)
    
    finding_count = 0
    if sniffer_results:
        summary_data = packet_sniffer.analyze_pcap_to_json(sniffer_results, target, user_id=user_identifier)
        if summary_data:
             finding_count = len(summary_data.get("security_anomaly_report", {}).get("port_scans", []))
             packet_sniffer.save_json_report(summary_data, output_dir=user_dir, user_id=user_identifier, target=target)
             try:
                 pdf_generator.create_sniffer_report_pdf(str(user_paths["json_report"]), str(user_paths["pdf_report"]))
             except Exception as e:
                 logger.error(f"[!] [SCHEDULER] Sniffer PDF generation failed: {e}")

    scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration, report_path=str(user_paths["pdf_report"]) if sniffer_results else None)

    logger.info(f"[+] [SCHEDULER] Sniffer scheduled capture for {target} finished: {status}")


def _dispatch_sql(target, config, user, user_identifier, base_dir, timestamp=None):
    """Dispatch a SQL injection scan."""
    import os
    from core.extensions import db as primary_db
    from sqlalchemy import update as sa_update
    from models.models import User as UserModel
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
    log_id = scan_logger.log_scan_start(user.id, "SQLMap", target, scan_type=scan_type, origin="scheduled")

    start_time = time.time()
    # Ensure target has protocol
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    sql_results_file = sql_scanner.run_sql_scan(target, output_dir=user_dir, scan_mode=scan_type, user_id=user_identifier)
    duration = time.time() - start_time

    status = "Completed" if sql_results_file else "Failed"
    
    # Use the same output path helper as the scanner logic
    user_paths = sql_scanner.get_output_paths(user_dir, target=target, timestamp=timestamp)
    
    finding_count = 0
    if sql_results_file:
         # Logically finding vulnerabilities involves parsing the result file
         # For scheduler's purpose, we'll assume we have a way to count or just log completion
         # In sql_scanner, run_sql_scan returns the parsed JSON path
         if os.path.exists(sql_results_file):
             with open(sql_results_file, 'r') as f:
                 data = json.load(f)
                 finding_count = len(data.get("vulnerabilities", []))
             try:
                 pdf_generator.create_sql_report_pdf(sql_results_file, str(user_paths["pdf_report"]))
             except Exception as e:
                 logger.error(f"[!] [SCHEDULER] SQL PDF generation failed: {e}")

    scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration, report_path=str(user_paths["pdf_report"]) if sql_results_file else None)

    logger.info(f"[+] [SCHEDULER] SQL scan on {target} finished: {status}")


def _dispatch_semgrep(target, config, user, user_identifier, base_dir):
    """Dispatch a Semgrep SAST scan."""
    import os
    from core.extensions import db as primary_db
    from sqlalchemy import update as sa_update
    from models.models import User as UserModel
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
    log_id = scan_logger.log_scan_start(user.id, "Semgrep", target, scan_type=ruleset, origin="scheduled")

    start_time = time.time()
    # Semgrep scans local paths or repositories
    semgrep_results = semgrep_scanner.run_semgrep_scan(target, ruleset=ruleset, user_id=user_identifier)
    log_id = scan_logger.log_scan_start(user.id, "Semgrep", "Source Code", scan_type=ruleset, origin="scheduled")

    start_time = time.time()
    
    # Standardize target name for file grouping
    target_label = "ProjectSource"
    user_paths = semgrep_scanner.get_output_paths(user_dir, user_id=user_identifier, target=target_label, timestamp=timestamp)

    report_file = semgrep_scanner.run_semgrep_scan(
        target_input=target, 
        input_type="zip" if target.endswith('.zip') else "git",
        output_dir=user_dir,
        user_id=user_identifier,
        target=target_label,
        timestamp=timestamp
    )
    duration = time.time() - start_time

    status = "Completed" if report_file else "Failed"
    finding_count = 0
    if report_file and os.path.exists(report_file):
        try:
            with open(report_file, 'r') as f:
                data = json.load(f)
                finding_count = data.get('total_findings', 0)
            pdf_generator.create_semgrep_report_pdf(report_file, str(user_paths["pdf_report"]))
        except Exception as e:
            logger.error(f"[!] [SCHEDULER] Semgrep PDF generation failed: {e}")

    scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration, report_path=str(user_paths["pdf_report"]) if report_file else None)
    logger.info(f"[+] [SCHEDULER] Semgrep scan finished: {status}")


def _dispatch_api(target, config, user, user_identifier, base_dir, timestamp=None):
    """Dispatch an API scanner scan."""
    import os
    from core.extensions import db as primary_db
    from sqlalchemy import update as sa_update
    from models.models import User as UserModel
    from Services import api_scanner, scan_logger, pdf_generator

    definition_url = config.get('definition_url', target)
    auth_token = config.get('auth_token', None)

    user_dir = os.path.join(base_dir, 'results', user_identifier, 'api_scanner')
    os.makedirs(user_dir, exist_ok=True)

    primary_db.session.execute(
        sa_update(UserModel).where(UserModel.id == user.id)
        .values(scan_count_api=UserModel.scan_count_api + 1)
    )
    primary_db.session.commit()

    scan_logger.reset_log_file(user_identifier, "api_scanner")
    log_id = scan_logger.log_scan_start(user.id, "API Scanner", target, scan_type="Scheduled", origin="scheduled")

    start_time = time.time()
    
    user_paths = api_scanner.get_output_paths(user_dir, user_id=user_identifier, target=target, timestamp=timestamp)
    xml_report = str(user_paths["xml_report"])
    
    success = api_scanner.run_api_scan(target, definition_url, xml_report, user_identifier, auth_token=auth_token)
    duration = time.time() - start_time

    status = "Completed" if success else "Failed"
    finding_count = 0

    if success:
        report_data = api_scanner.parse_xml_report(xml_report, user_identifier)
        if report_data:
            json_path = api_scanner.save_json_report(report_data, user_dir, user_identifier, target=target, timestamp=timestamp)
            finding_count = len(report_data.get('findings', []))
            if json_path:
                try:
                    pdf_generator.create_api_report_pdf(json_path, str(user_paths["pdf_report"]))
                except Exception as e:
                    logger.error(f"[!] [SCHEDULER] API PDF generation failed: {e}")

    scan_logger.log_scan_end(log_id, status=status, finding_count=finding_count, duration=duration, report_path=str(user_paths["pdf_report"]) if success else None)
    logger.info(f"[+] [SCHEDULER] API scan on {target} finished: {status}")


def _dispatch_killchain(target, config, user, user_identifier, base_dir, timestamp=None):
    """Dispatch a Kill Chain audit."""
    import os
    from Services.killchain_service import killchain_service
    from Services import scan_logger
    from core.extensions import db as primary_db

    profile_name = config.get('profile', 'Full Scan')
    aggression = config.get('aggression', 'Normal')

    user_dir = os.path.join(base_dir, 'results', user_identifier, 'killchain')
    os.makedirs(user_dir, exist_ok=True)

    # Increment counter
    user.scan_count_killchain += 1
    primary_db.session.commit()

    scan_logger.reset_log_file(user_identifier, "killchain")
    log_id = scan_logger.log_scan_start(user.id, "Kill Chain", target, scan_type=f"{profile_name} ({aggression})", origin="scheduled")

    scan_id = str(uuid.uuid4())[:8]
    queue_id = f"{user_identifier}::{scan_id}"

    # Run synchronously within the scheduler thread
    killchain_service.run_job(
        target=target,
        profile_name=profile_name,
        aggression_level=aggression,
        queue_id=queue_id,
        user_output_dir=user_dir,
        log_id=log_id,
        app=_app,
        timestamp=timestamp # Pass timestamp if service supports it
    )

    logger.info(f"[+] [SCHEDULER] Kill Chain audit on {target} completed.")


def reload_all_jobs(app):
    """
    On startup, re-register all enabled ScheduledScanJob rows.
    Ensures jobs survive server restarts.
    """
    with app.app_context():
        try:
            from models.scheduler_models import ScheduledScanJob
            enabled_jobs = ScheduledScanJob.query.filter_by(is_enabled=True).all()

            # Build the set of deterministic IDs we EXPECT to exist
            expected_ids = {f"scheduled_scan_{j.id}" for j in enabled_jobs}
            expected_ids.add('consent_watchdog')

            # Purge any orphaned APScheduler jobs (stale UUID-suffixed ones from old restarts)
            for aps_job in _scheduler.get_jobs():
                if aps_job.id.startswith('scheduled_scan_') and aps_job.id not in expected_ids:
                    logger.warning(f"[!] [SCHEDULER] Removing orphaned APScheduler job: {aps_job.id}")
                    try:
                        _scheduler.remove_job(aps_job.id)
                    except Exception:
                        pass

            if not enabled_jobs:
                logger.info("[*] [SCHEDULER] No enabled jobs found to reload.")
                return

            for job_row in enabled_jobs:
                aps_id = register_job(job_row)
                if aps_id:
                    job_row.apscheduler_job_id = aps_id
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


def _consent_watchdog():
    """
    Background task that monitors upcoming jobs and sends consent emails 
    30 minutes before their scheduled execution.
    """
    global _app, _scheduler
    if not _app or not _scheduler:
        return

    with _app.app_context():
        try:
            from models.scheduler_models import ScheduledScanJob, ProfileTarget, ScanProfile
            import datetime as dt

            # 1. Update next_run_at for all active jobs from APScheduler state
            # This ensures our DB query is accurate
            active_jobs = ScheduledScanJob.query.filter_by(is_enabled=True).all()
            for job in active_jobs:
                if job.apscheduler_job_id:
                    aps_job = _scheduler.get_job(job.apscheduler_job_id)
                    if aps_job and aps_job.next_run_time:
                        job.next_run_at = aps_job.next_run_time.replace(tzinfo=None)
                        logger.debug(f"[*] [SCHEDULER] Sync: Job {job.id} next run at {job.next_run_at}")
            db.session.commit()

            # 2. Find jobs starting in the next 30-31 minutes
            now = datetime.now(IST).replace(tzinfo=None)
            window_start = now + dt.timedelta(minutes=0)
            window_end = now + dt.timedelta(minutes=31)
            
            logger.debug(f"[*] [SCHEDULER] Watchdog run at {now} (Window: {window_start} to {window_end})")

            upcoming_jobs = ScheduledScanJob.query.filter(
                ScheduledScanJob.is_enabled == True,
                ScheduledScanJob.schedule_type != 'once'
            ).all()

            matched_jobs = []
            for job in upcoming_jobs:
                if job.next_run_at:
                    is_in_window = window_start <= job.next_run_at <= window_end
                    logger.debug(f"[*] [SCHEDULER] Job {job.id} next_run={job.next_run_at} | window=[{window_start} to {window_end}] | match={is_in_window}")
                    if is_in_window:
                        matched_jobs.append(job)

            if matched_jobs:
                logger.info(f"[*] [SCHEDULER] Found {len(matched_jobs)} upcoming jobs in window.")
            
            for job in matched_jobs:
                # Get targets requiring consent
                targets = ProfileTarget.query.filter_by(profile_id=job.profile_id, requires_consent=True).all()
                logger.info(f"[*] [SCHEDULER] Job {job.id} has {len(targets)} targets requiring consent.")
                
                if not targets:
                    continue

                profile = ScanProfile.query.get(job.profile_id)
                for target_row in targets:
                    # Trigger consent request if not already approved/pending
                    from models.scheduler_models import ScanConsentToken
                    approved = ScanConsentToken.query.filter_by(
                        job_id=job.id, 
                        target_id=target_row.id, 
                        status='approved'
                    ).first()
                    
                    if not approved:
                        logger.info(f"[*] [SCHEDULER] Watchdog: Triggering 30m consent request for {target_row.target_url}")
                        _trigger_consent_request(job, target_row, profile)
                    else:
                        logger.info(f"[*] [SCHEDULER] Watchdog: Consent already approved for {target_row.target_url}")

        except Exception as e:
            logger.error(f"[!] [SCHEDULER] Watchdog error: {e}")
            traceback.print_exc()
