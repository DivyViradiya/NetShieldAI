"""
Scheduler Blueprint
===================
Full CRUD API + UI page for managing scan profiles, configs, targets,
recipients, and scheduled jobs.
"""

import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
IST = ZoneInfo("Asia/Kolkata")

from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
from core.logger_setup import logger
from core.extensions import db, limiter
from models.scheduler_models import (
    ScanProfile, ProfileScanConfig,
    ProfileTarget, ProfileRecipient, ScheduledScanJob
)
from Services import scheduler_service

scheduler_bp = Blueprint('scheduler_bp', __name__)


# ==========================================
# Helper: Ownership check
# ==========================================

def _get_profile_or_404(profile_id):
    """Fetch profile and verify ownership. Returns (profile, error_response)."""
    profile = db.session.get(ScanProfile, profile_id)
    if not profile:
        return None, (jsonify({"status": "error", "message": "Profile not found."}), 404)
    if profile.user_id != current_user.id:
        return None, (jsonify({"status": "error", "message": "Access denied."}), 403)
    return profile, None


# ==========================================
# UI Route
# ==========================================

@scheduler_bp.route('/')
@login_required
def scheduler_page():
    """Render the scheduler dashboard."""
    logger.info(f"[*] Accessing Scheduler Page (User: {current_user.username})")
    return render_template('scheduler/scheduler.html')


# ==========================================
# Profiles CRUD
# ==========================================

@scheduler_bp.route('/api/profiles', methods=['GET'])
@login_required
def list_profiles():
    """List all profiles owned by the current user."""
    profiles = ScanProfile.query.filter_by(user_id=current_user.id)\
        .order_by(ScanProfile.updated_at.desc()).all()
    return jsonify({
        "status": "success",
        "profiles": [p.to_dict() for p in profiles]
    })


@scheduler_bp.route('/api/profiles', methods=['POST'])
@login_required
def create_profile():
    """Create a new scan profile."""
    data = request.get_json()
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({"status": "error", "message": "Profile name is required."}), 400

    profile = ScanProfile(
        user_id=current_user.id,
        name=name,
        description=(data.get('description') or '').strip() or None,
        is_active=data.get('is_active', True)
    )
    db.session.add(profile)
    db.session.commit()

    logger.info(f"[+] Profile '{name}' created by {current_user.username}")
    return jsonify({"status": "success", "profile": profile.to_dict()}), 201


@scheduler_bp.route('/api/profiles/<int:profile_id>', methods=['PUT'])
@login_required
def update_profile(profile_id):
    """Update an existing profile."""
    profile, err = _get_profile_or_404(profile_id)
    if err:
        return err

    data = request.get_json()
    if 'name' in data:
        name = data['name'].strip()
        if not name:
            return jsonify({"status": "error", "message": "Profile name cannot be empty."}), 400
        profile.name = name
    if 'description' in data:
        profile.description = (data['description'] or '').strip() or None
    if 'is_active' in data:
        profile.is_active = bool(data['is_active'])

    profile.updated_at = datetime.now(IST).replace(tzinfo=None)
    db.session.commit()

    return jsonify({"status": "success", "profile": profile.to_dict()})


@scheduler_bp.route('/api/profiles/<int:profile_id>', methods=['DELETE'])
@login_required
def delete_profile(profile_id):
    """Delete a profile and all associated configs, targets, recipients, jobs."""
    profile, err = _get_profile_or_404(profile_id)
    if err:
        return err

    # Collect IDs before committing deletion
    aps_ids = [job.apscheduler_job_id for job in profile.jobs if job.apscheduler_job_id]

    db.session.delete(profile)
    db.session.commit()

    # Unregister after DB lock is released
    for aps_id in aps_ids:
        scheduler_service.unregister_job(aps_id)

    logger.info(f"[-] Profile '{profile.name}' deleted by {current_user.username}")
    return jsonify({"status": "success", "message": "Profile deleted."})


# ==========================================
# Scan Configs CRUD
# ==========================================

@scheduler_bp.route('/api/profiles/<int:profile_id>/configs', methods=['POST'])
@login_required
def add_config(profile_id):
    """Add a scan config to a profile."""
    profile, err = _get_profile_or_404(profile_id)
    if err:
        return err

    data = request.get_json()
    module = (data.get('module') or '').strip().lower()

    if module not in ProfileScanConfig.VALID_MODULES:
        return jsonify({
            "status": "error",
            "message": f"Invalid module. Must be one of: {', '.join(ProfileScanConfig.VALID_MODULES)}"
        }), 400

    config_data = data.get('config', {})

    config = ProfileScanConfig(
        profile_id=profile.id,
        module=module,
        config_json=json.dumps(config_data),
        display_label=(data.get('display_label') or '').strip() or f"{module.upper()} Config"
    )
    db.session.add(config)
    profile.updated_at = datetime.now(IST).replace(tzinfo=None)
    db.session.commit()

    return jsonify({"status": "success", "config": config.to_dict()}), 201


@scheduler_bp.route('/api/profiles/<int:profile_id>/configs/<int:config_id>', methods=['PUT'])
@login_required
def update_config(profile_id, config_id):
    """Update a scan config."""
    profile, err = _get_profile_or_404(profile_id)
    if err:
        return err

    config = ProfileScanConfig.query.filter_by(id=config_id, profile_id=profile.id).first()
    if not config:
        return jsonify({"status": "error", "message": "Config not found."}), 404

    data = request.get_json()
    if 'module' in data:
        module = data['module'].strip().lower()
        if module not in ProfileScanConfig.VALID_MODULES:
            return jsonify({"status": "error", "message": "Invalid module."}), 400
        config.module = module
    if 'config' in data:
        config.config_json = json.dumps(data['config'])
    if 'display_label' in data:
        config.display_label = (data['display_label'] or '').strip()

    profile.updated_at = datetime.now(IST).replace(tzinfo=None)
    db.session.commit()

    return jsonify({"status": "success", "config": config.to_dict()})


@scheduler_bp.route('/api/profiles/<int:profile_id>/configs/<int:config_id>', methods=['DELETE'])
@login_required
def delete_config(profile_id, config_id):
    """Remove a scan config from a profile."""
    profile, err = _get_profile_or_404(profile_id)
    if err:
        return err

    config = ProfileScanConfig.query.filter_by(id=config_id, profile_id=profile.id).first()
    if not config:
        return jsonify({"status": "error", "message": "Config not found."}), 404

    db.session.delete(config)
    profile.updated_at = datetime.now(IST).replace(tzinfo=None)
    db.session.commit()

    return jsonify({"status": "success", "message": "Config removed."})


# ==========================================
# Targets CRUD
# ==========================================

@scheduler_bp.route('/api/profiles/<int:profile_id>/targets', methods=['POST'])
@login_required
def add_target(profile_id):
    """Add a target to a profile."""
    profile, err = _get_profile_or_404(profile_id)
    if err:
        return err

    data = request.get_json()
    target_url = (data.get('target_url') or '').strip()
    if not target_url:
        return jsonify({"status": "error", "message": "Target URL is required."}), 400

    # Check for duplicate
    existing = ProfileTarget.query.filter_by(profile_id=profile.id, target_url=target_url).first()
    if existing:
        return jsonify({"status": "error", "message": "Target already exists in this profile."}), 409

    requires_consent = data.get('requires_consent', False)
    consent_email = (data.get('consent_email') or '').strip()
    if requires_consent and not consent_email:
        return jsonify({"status": "error", "message": "Consent email is required if consent check is enabled."}), 400

    target = ProfileTarget(
        profile_id=profile.id, 
        target_url=target_url,
        requires_consent=requires_consent,
        consent_email=consent_email if requires_consent else None
    )
    db.session.add(target)
    profile.updated_at = datetime.now(IST).replace(tzinfo=None)
    db.session.commit()

    return jsonify({"status": "success", "target": target.to_dict()}), 201


@scheduler_bp.route('/api/profiles/<int:profile_id>/targets/<int:target_id>', methods=['DELETE'])
@login_required
def remove_target(profile_id, target_id):
    """Remove a target from a profile."""
    profile, err = _get_profile_or_404(profile_id)
    if err:
        return err

    target = ProfileTarget.query.filter_by(id=target_id, profile_id=profile.id).first()
    if not target:
        return jsonify({"status": "error", "message": "Target not found."}), 404

    db.session.delete(target)
    profile.updated_at = datetime.now(IST).replace(tzinfo=None)
    db.session.commit()

    return jsonify({"status": "success", "message": "Target removed."})


@scheduler_bp.route('/api/profiles/<int:profile_id>/targets/<int:target_id>', methods=['PUT'])
@login_required
def update_target(profile_id, target_id):
    """Update an existing target's URL."""
    profile, err = _get_profile_or_404(profile_id)
    if err:
        return err

    target = ProfileTarget.query.filter_by(id=target_id, profile_id=profile.id).first()
    if not target:
        return jsonify({"status": "error", "message": "Target not found."}), 404

    data = request.get_json()
    target_url = (data.get('target_url') or '').strip()
    if not target_url:
        return jsonify({"status": "error", "message": "Target URL is required."}), 400

    target.target_url = target_url
    target.requires_consent = data.get('requires_consent', False)
    target.consent_email = (data.get('consent_email') or '').strip() if target.requires_consent else None
    profile.updated_at = datetime.now(IST).replace(tzinfo=None)
    db.session.commit()

    return jsonify({"status": "success", "target": target.to_dict()})


# ==========================================
# Recipients CRUD
# ==========================================

@scheduler_bp.route('/api/profiles/<int:profile_id>/recipients', methods=['POST'])
@login_required
def add_recipient(profile_id):
    """Add a recipient to a profile."""
    profile, err = _get_profile_or_404(profile_id)
    if err:
        return err

    data = request.get_json()
    email = (data.get('email') or '').strip()
    if not email or '@' not in email:
        return jsonify({"status": "error", "message": "Valid email is required."}), 400

    role = data.get('role', 'technical')
    if role not in ('technical', 'executive'):
        role = 'technical'

    # Check for duplicate
    existing = ProfileRecipient.query.filter_by(profile_id=profile.id, email=email).first()
    if existing:
        return jsonify({"status": "error", "message": "Recipient already exists in this profile."}), 409

    recipient = ProfileRecipient(profile_id=profile.id, email=email, role=role)
    db.session.add(recipient)
    profile.updated_at = datetime.now(IST).replace(tzinfo=None)
    db.session.commit()

    return jsonify({"status": "success", "recipient": recipient.to_dict()}), 201


@scheduler_bp.route('/api/profiles/<int:profile_id>/recipients/<int:recipient_id>', methods=['DELETE'])
@login_required
def remove_recipient(profile_id, recipient_id):
    """Remove a recipient from a profile."""
    profile, err = _get_profile_or_404(profile_id)
    if err:
        return err

    recipient = ProfileRecipient.query.filter_by(id=recipient_id, profile_id=profile.id).first()
    if not recipient:
        return jsonify({"status": "error", "message": "Recipient not found."}), 404

    db.session.delete(recipient)
    profile.updated_at = datetime.now(IST).replace(tzinfo=None)
    db.session.commit()

    return jsonify({"status": "success", "message": "Recipient removed."})


# ==========================================
# Jobs CRUD
# ==========================================

@scheduler_bp.route('/api/jobs', methods=['GET'])
@login_required
def list_jobs():
    """List all scheduled jobs for the current user."""
    jobs = ScheduledScanJob.query.join(ScanProfile)\
        .filter(ScanProfile.user_id == current_user.id)\
        .order_by(ScheduledScanJob.created_at.desc()).all()

    result = []
    for job in jobs:
        job_dict = job.to_dict()
        job_dict['profile_name'] = job.profile.name if job.profile else 'Unknown'
        result.append(job_dict)

    return jsonify({"status": "success", "jobs": result})


@scheduler_bp.route('/api/jobs', methods=['POST'])
@login_required
def create_job():
    """Create a new scheduled job."""
    data = request.get_json()
    profile_id = data.get('profile_id')

    if not profile_id:
        return jsonify({"status": "error", "message": "profile_id is required."}), 400

    profile, err = _get_profile_or_404(profile_id)
    if err:
        return err

    schedule_type = data.get('schedule_type', '').strip().lower()
    if schedule_type not in ScheduledScanJob.VALID_SCHEDULE_TYPES:
        return jsonify({
            "status": "error",
            "message": f"Invalid schedule_type. Must be one of: {', '.join(ScheduledScanJob.VALID_SCHEDULE_TYPES)}"
        }), 400

    # Parse schedule params
    cron_hour = int(data.get('cron_hour', 0))
    cron_minute = int(data.get('cron_minute', 0))
    cron_day_of_week = data.get('cron_day_of_week')
    cron_day_of_month = data.get('cron_day_of_month')
    interval_minutes = data.get('interval_minutes')
    cron_expression = data.get('cron_expression')
    one_shot_at = None

    if schedule_type == 'once':
        one_shot_str = data.get('one_shot_at')
        if not one_shot_str:
            return jsonify({"status": "error", "message": "one_shot_at datetime is required for one-shot scheduling."}), 400
        try:
            one_shot_at = datetime.fromisoformat(one_shot_str)
            if one_shot_at.tzinfo is not None:
                one_shot_at = one_shot_at.astimezone(IST).replace(tzinfo=None)
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "Invalid one_shot_at format. Use ISO format."}), 400

    if schedule_type == 'weekly' and not cron_day_of_week:
        return jsonify({"status": "error", "message": "cron_day_of_week is required for weekly scheduling."}), 400

    if schedule_type == 'monthly':
        if cron_day_of_month is None:
            return jsonify({"status": "error", "message": "cron_day_of_month is required for monthly scheduling."}), 400
        # Now stored as string (e.g., "1,15,30")
        cron_day_of_month = str(cron_day_of_month)

    job = ScheduledScanJob(
        profile_id=profile.id,
        schedule_type=schedule_type,
        cron_hour=cron_hour,
        cron_minute=cron_minute,
        cron_day_of_week=cron_day_of_week,
        cron_day_of_month=cron_day_of_month,
        interval_minutes=interval_minutes,
        cron_expression=cron_expression,
        one_shot_at=one_shot_at,
        is_enabled=True,
        send_report_email=bool(data.get('send_report_email', True))
    )
    db.session.add(job)
    db.session.commit()  # [FIX] Commit immediately to release the SQLite write lock before calling APScheduler

    # Register with APScheduler (this will attempt its own write to the same DB)
    aps_id = scheduler_service.register_job(job)
    if aps_id:
        job.apscheduler_job_id = aps_id

        # Store next run time
        sched = scheduler_service.get_scheduler()
        if sched:
            try:
                aps_job = sched.get_job(aps_id)
                if aps_job and aps_job.next_run_time:
                    job.next_run_at = aps_job.next_run_time.replace(tzinfo=None)
            except Exception:
                pass

        db.session.commit() # Save the APS job ID

    job_dict = job.to_dict()
    job_dict['profile_name'] = profile.name
    logger.info(f"[+] Scheduled job created: {schedule_type} for profile '{profile.name}'")

    return jsonify({"status": "success", "job": job_dict}), 201


@scheduler_bp.route('/api/jobs/<int:job_id>/toggle', methods=['PUT'])
@login_required
def toggle_job(job_id):
    """Enable or disable a scheduled job."""
    job = db.session.get(ScheduledScanJob, job_id)
    if not job:
        return jsonify({"status": "error", "message": "Job not found."}), 404

    # Verify ownership through profile
    profile, err = _get_profile_or_404(job.profile_id)
    if err:
        return err

    job.is_enabled = not job.is_enabled
    db.session.commit() # Commit state change first

    if job.is_enabled:
        # Re-register
        aps_id = scheduler_service.register_job(job)
        if aps_id:
            job.apscheduler_job_id = aps_id
            sched = scheduler_service.get_scheduler()
            if sched:
                try:
                    aps_job = sched.get_job(aps_id)
                    if aps_job and aps_job.next_run_time:
                        job.next_run_at = aps_job.next_run_time.replace(tzinfo=None)
                except Exception:
                    pass
            db.session.commit() # Save the new APS ID
    else:
        # Unregister
        if job.apscheduler_job_id:
            scheduler_service.unregister_job(job.apscheduler_job_id)
            job.apscheduler_job_id = None # Clear it
            job.next_run_at = None
            db.session.commit()

    return jsonify({
        "status": "success",
        "is_enabled": job.is_enabled,
        "job": job.to_dict()
    })


@scheduler_bp.route('/api/jobs/<int:job_id>', methods=['PUT'])
@login_required
def update_job(job_id):
    """Update an existing scheduled job's parameters."""
    job = db.session.get(ScheduledScanJob, job_id)
    if not job:
        return jsonify({"status": "error", "message": "Job not found."}), 404

    profile, err = _get_profile_or_404(job.profile_id)
    if err:
        return err

    data = request.get_json()
    
    # Update schedule parameters
    if 'schedule_type' in data:
        st = data['schedule_type'].strip().lower()
        if st in ScheduledScanJob.VALID_SCHEDULE_TYPES:
            job.schedule_type = st
            
    if 'cron_hour' in data: job.cron_hour = int(data['cron_hour'])
    if 'cron_minute' in data: job.cron_minute = int(data['cron_minute'])
    if 'cron_day_of_week' in data: job.cron_day_of_week = data['cron_day_of_week']
    if 'cron_day_of_month' in data: job.cron_day_of_month = str(data['cron_day_of_month'])
    if 'interval_minutes' in data: job.interval_minutes = data['interval_minutes']
    if 'cron_expression' in data: job.cron_expression = data['cron_expression']
    
    if 'one_shot_at' in data:
        one_shot_str = data['one_shot_at']
        if one_shot_str:
            try:
                dt = datetime.fromisoformat(one_shot_str)
                if dt.tzinfo is not None:
                    dt = dt.astimezone(IST).replace(tzinfo=None)
                job.one_shot_at = dt
            except (ValueError, TypeError):
                pass

    if 'send_report_email' in data:
        job.send_report_email = bool(data['send_report_email'])

    db.session.commit()

    # Re-register with APScheduler if enabled
    if job.is_enabled:
        if job.apscheduler_job_id:
            scheduler_service.unregister_job(job.apscheduler_job_id)
        
        aps_id = scheduler_service.register_job(job)
        if aps_id:
            job.apscheduler_job_id = aps_id
            sched = scheduler_service.get_scheduler()
            if sched:
                try:
                    aps_job = sched.get_job(aps_id)
                    if aps_job and aps_job.next_run_time:
                        job.next_run_at = aps_job.next_run_time.replace(tzinfo=None)
                except Exception:
                    pass
            db.session.commit()

    return jsonify({"status": "success", "job": job.to_dict()})


@scheduler_bp.route('/api/jobs/<int:job_id>', methods=['DELETE'])
@login_required
def delete_job(job_id):
    """Delete a scheduled job."""
    job = db.session.get(ScheduledScanJob, job_id)
    if not job:
        return jsonify({"status": "error", "message": "Job not found."}), 404

    profile, err = _get_profile_or_404(job.profile_id)
    if err:
        return err

    aps_id = job.apscheduler_job_id

    db.session.delete(job)
    db.session.commit()

    if aps_id:
        scheduler_service.unregister_job(aps_id)

    return jsonify({"status": "success", "message": "Job deleted."})


@scheduler_bp.route('/api/jobs/<int:job_id>/history', methods=['GET'])
@login_required
def job_history(job_id):
    """Get past runs for a job — queries ScanLog from the primary DB with filtering."""
    job = db.session.get(ScheduledScanJob, job_id)
    if not job:
        return jsonify({"status": "error", "message": "Job not found."}), 404

    profile, err = _get_profile_or_404(job.profile_id)
    if err:
        return err

    # Filters from query params
    scanner_type = request.args.get('scanner_type')
    target_q = request.args.get('target_q')
    status_filter = request.args.get('status')

    # Get target URLs and tools for this profile to restrict results to this specific scan config
    target_urls = [t.target_url for t in profile.targets]
    tools = [c.module for c in profile.configs]

    # Query ScanLog from primary DB for this user's scans
    from models.models import ScanLog
    query = ScanLog.query.filter_by(user_id=current_user.id, origin='scheduled')

    if target_urls:
        query = query.filter(ScanLog.target.in_(target_urls))
    if tools:
        query = query.filter(db.func.lower(ScanLog.tool_name).in_([t.lower() for t in tools]))

    if scanner_type and scanner_type != 'all':
        query = query.filter(ScanLog.tool_name.ilike(f"%{scanner_type}%"))
    if target_q:
        query = query.filter(ScanLog.target.ilike(f"%{target_q}%"))
    if status_filter:
        query = query.filter_by(status=status_filter)

    logs = query.order_by(ScanLog.start_time.desc()).limit(50).all()

    from models.scheduler_models import ReportDeliveryLink
    history = [{
        'id': log.id,
        'tool_name': log.tool_name,
        'target': log.target,
        'status': log.status,
        'scan_type': log.scan_type,
        'start_time': log.start_time.isoformat() if log.start_time else None,
        'end_time': log.end_time.isoformat() if log.end_time else None,
        'duration': round(log.duration_seconds, 1) if log.duration_seconds else 0,
        'finding_count': log.finding_count or 0,
        'has_report': bool(log.report_path),
        'delivery_logs': [{
            'email': l.recipient_email,
            'opened_at': l.opened_at.isoformat() if l.opened_at else None,
            'ip': l.opened_from_ip
        } for l in ReportDeliveryLink.query.filter_by(log_id=log.id).all()]
    } for log in logs]

    return jsonify({"status": "success", "history": history})


@scheduler_bp.route('/api/reports', methods=['GET'])
@login_required
def list_all_reports():
    """Get all past runs across all missions — queries ScanLog from the primary DB with filtering."""
    # Filters from query params
    scanner_type = request.args.get('scanner_type')
    target_q = request.args.get('target_q')
    status = request.args.get('status')

    # Query ScanLog from primary DB
    from models.models import ScanLog
    query = ScanLog.query.filter_by(user_id=current_user.id, origin='scheduled')

    if scanner_type and scanner_type != 'all':
        query = query.filter(ScanLog.tool_name.ilike(f"%{scanner_type}%"))
    if target_q:
        query = query.filter(ScanLog.target.ilike(f"%{target_q}%"))
    if status and status != 'all':
        query = query.filter(ScanLog.status == status)

    logs = query.order_by(ScanLog.start_time.desc()).limit(100).all()

    from models.scheduler_models import ReportDeliveryLink
    history = [{
        'id': log.id,
        'tool_name': log.tool_name,
        'target': log.target,
        'status': log.status,
        'scan_type': log.scan_type,
        'start_time': log.start_time.isoformat() if log.start_time else None,
        'end_time': log.end_time.isoformat() if log.end_time else None,
        'duration': round(log.duration_seconds, 1) if log.duration_seconds else 0,
        'finding_count': log.finding_count or 0,
        'has_report': bool(log.report_path),
        'delivery_logs': [{
            'email': l.recipient_email,
            'opened_at': l.opened_at.isoformat() if l.opened_at else None,
            'ip': l.opened_from_ip
        } for l in ReportDeliveryLink.query.filter_by(log_id=log.id).all()]
    } for log in logs]

    return jsonify({"status": "success", "history": history})


# ==========================================
# Module Schema Endpoint
# ==========================================

@scheduler_bp.route('/api/modules', methods=['GET'])
@login_required
def get_modules():
    """Returns available modules and their config schemas for the frontend."""
    return jsonify({
        "status": "success",
        "modules": ProfileScanConfig.VALID_MODULES,
        "schemas": ProfileScanConfig.MODULE_SCHEMAS
    })
@scheduler_bp.route('/api/profiles/<int:profile_id>/trigger', methods=['POST'])
@login_required
def trigger_profile_scan(profile_id):
    """Manually trigger all jobs/configs associated with a profile."""
    from models.scheduler_models import ScanProfile, ScheduledScanJob
    from Services.scheduler_service import _execute_scheduled_scan_wrapper
    import threading

    profile, err = _get_profile_or_404(profile_id)
    if err:
        return err
    
    # We trigger the jobs in the background to avoid blocking the UI
    for job in profile.jobs:
        thread = threading.Thread(
            target=_execute_scheduled_scan_wrapper,
            args=(job.id, True),
            daemon=True
        )
        thread.start()
            
    return jsonify({"status": "success", "message": f"Scan triggered for profile '{profile.name}'"})


@scheduler_bp.route('/api/deliver/<token>', methods=['GET'])
@limiter.limit("5 per minute")
def deliver_report(token):
    """
    Public, secure route to download a report.
    Logs access for compliance (SOC-2).
    """
    from models.scheduler_models import ReportDeliveryLink, DeliveryAuditLog
    from models.models import ScanLog
    from flask import send_file, request, jsonify, render_template
    from datetime import datetime
    import os

    audit_log = DeliveryAuditLog(
        token_attempted=token,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string if request.user_agent else "Unknown",
        status="invalid"
    )
    db.session.add(audit_log)

    link = ReportDeliveryLink.query.filter_by(token=token).first()
    if not link:
        audit_log.status = "invalid"
        db.session.commit()
        return render_template('scheduler/delivery_result.html', status='invalid', message='Invalid delivery link.'), 404

    audit_log.link_id = link.id

    if link.is_used:
        audit_log.status = "already_used"
        db.session.commit()
        return render_template('scheduler/delivery_result.html', status='used', message='This link has already been used to download the report.'), 410

    if link.is_expired():
        audit_log.status = "expired"
        db.session.commit()
        return render_template('scheduler/delivery_result.html', status='expired', message='This link has expired (48h valid).'), 410

    # Fetch report
    log = db.session.get(ScanLog, link.log_id)
    if not log:
        audit_log.status = "error_file_missing"
        db.session.commit()
        return render_template('scheduler/delivery_result.html', status='invalid', message='Report file not found on server.'), 404

    # Resolve Correct File Path
    is_exec = getattr(link, 'report_type', 'normal') == 'executive'
    if is_exec:
        target_path = getattr(log, 'executive_summary_path', None) or log.report_path.replace(".pdf", "_executive.pdf")
    else:
        target_path = log.report_path

    if not target_path or not os.path.exists(target_path):
        audit_log.status = "error_file_missing"
        db.session.commit()
        return render_template('scheduler/delivery_result.html', status='invalid', message='Report file not found on server.'), 404

    # Success
    if not link.opened_at:
        link.opened_at = datetime.now(IST).replace(tzinfo=None)
        link.opened_from_ip = request.remote_addr
    
    link.is_used = True
    audit_log.status = "success"
    db.session.commit()

    safe_tool = log.tool_name.replace(" ", "_").lower()
    suffix = "_executive" if is_exec else ""
    report_name = f"NetShield_{safe_tool}_report_{log.id}{suffix}.pdf"

    return send_file(
        target_path,
        as_attachment=True,
        download_name=report_name,
        mimetype='application/pdf'
    )

@scheduler_bp.route('/api/reports/<int:log_id>/resend_delivery', methods=['POST'])
@login_required
def resend_report_link(log_id):
    """Admin/Owner endpoint to regenerate and resend a report delivery link."""
    from models.models import ScanLog
    log = db.session.get(ScanLog, log_id)
    if not log or log.user_id != current_user.id:
        return jsonify({"status": "error", "message": "Report not found or access denied."}), 404

    data = request.get_json() or {}
    recipient_email = data.get("recipient_email")
    if not recipient_email:
        return jsonify({"status": "error", "message": "recipient_email is required."}), 400

    from Services.scheduler_service import resend_report_delivery
    success, msg = resend_report_delivery(log_id, recipient_email)
    
    if success:
        return jsonify({"status": "success", "message": msg})
    else:
        return jsonify({"status": "error", "message": msg}), 500


@scheduler_bp.route('/api/reports/<int:log_id>/download', methods=['GET'])
@login_required
def download_report(log_id):
    """Serve the generated PDF report for a scan log."""
    from models.models import ScanLog
    from flask import send_file
    import os

    log = db.session.get(ScanLog, log_id)
    if not log or log.user_id != current_user.id:
        return jsonify({"status": "error", "message": "Report not found."}), 404

    if not log.report_path or not os.path.exists(log.report_path):
        return jsonify({"status": "error", "message": "Report file does not exist on server."}), 404

    # Sanitize tool name for filename
    safe_tool = log.tool_name.replace(" ", "_").lower()
    report_name = f"NetShield_{safe_tool}_report_{log.id}.pdf"

    return send_file(
        log.report_path,
        as_attachment=True,
        download_name=report_name,
        mimetype='application/pdf'
    )


@scheduler_bp.route('/api/reports/<int:log_id>/executive_summary', methods=['GET'])
@login_required
def download_executive_summary_report(log_id):
    """Generate and serve the Executive Summary PDF for a scan log."""
    from models.models import ScanLog
    from flask import send_file
    import os
    import requests
    from Services.pdf_generator import create_executive_summary_report_pdf
    from werkzeug.utils import secure_filename

    # Fix: Hardcode or load locally
    SERVER_PROXY_URL = "http://127.0.0.1:5000"

    log = db.session.get(ScanLog, log_id)
    if not log or log.user_id != current_user.id:
        return jsonify({"status": "error", "message": "Report not found."}), 404

    if not log.report_path or not os.path.exists(log.report_path):
        return jsonify({"status": "error", "message": "Original report file does not exist on server."}), 404

    # Optimize Pathing
    exec_path = log.report_path.replace(".pdf", "_executive.pdf")
    exec_filename = os.path.basename(exec_path)

    if os.path.exists(exec_path):
        logger.info(f"[*] Serving cached Executive Summary: {exec_path}")
        return send_file(exec_path, as_attachment=True, download_name=exec_filename, mimetype='application/pdf')

    # Generate it
    logger.info(f"[*] Generating Executive Summary PDF for Log ID {log_id}")
    
    try:
        user_id_safe = f"{secure_filename(current_user.username)}_{current_user.id}"
        
        # Optimize Parameters: Use file_path (skips upload) and background=False (sync summary)
        params = {
            'llm_mode': 'gemini-2.5-flash',
            'user_id': user_id_safe,
            'file_path': os.path.abspath(log.report_path), # Absolute path needed
            'background': False
        }
        
        proxy_url = f"{SERVER_PROXY_URL}/upload_report"
        
        logger.info(f"[*] Calling AI chatbot backend for sync summarization (Path: {log.report_path})")
        # No 'files' argument needed with file_path
        resp = requests.post(proxy_url, params=params, timeout=45) 
        resp.raise_for_status()
        
        data = resp.json()
        summary_text = data.get('summary')
        if not summary_text or "Analysis and summary are being generated" in summary_text:
             logger.warning(f"[!] Chatbot backend returned placeholder or no summary. Response: {data}")
             return jsonify({"status": "error", "message": "Failed to generate synchronous summary from AI."}), 500

        # 3. Create PDF
        metadata = {
            "target": log.target,
            "tool_name": log.tool_name,
            "date": log.start_time.strftime("%Y-%m-%d %H:%M:%S") if log.start_time else "N/A"
        }
        
        success = create_executive_summary_report_pdf(summary_text, metadata, exec_path, user_id=user_id_safe)
        if not success:
             return jsonify({"status": "error", "message": "Failed to create Executive Summary PDF."}), 500

        return send_file(exec_path, as_attachment=True, download_name=exec_filename, mimetype='application/pdf')

    except requests.exceptions.HTTPError as e:
         logger.error(f"HTTP error creating executive summary: {e.response.text if hasattr(e, 'response') else e}", exc_info=True)
         return jsonify({"status": "error", "message": f"AI Backend Error: {str(e)}"}), 502
    except Exception as e:
         logger.error(f"Error creating executive summary: {e}", exc_info=True)
         return jsonify({"status": "error", "message": f"Error: {str(e)}"}), 500


@scheduler_bp.route('/api/reports/<int:log_id>/executive_summary/status', methods=['GET'])
@login_required
def get_executive_summary_status(log_id):
    """Check if an executive summary PDF already exists (cached) for this scan log.
    Used by the frontend to restore 'ready' state on page reload."""
    from models.models import ScanLog
    import os

    log = db.session.get(ScanLog, log_id)
    if not log or log.user_id != current_user.id:
        return jsonify({"status": "error", "message": "Report not found."}), 404

    if not log.report_path:
        return jsonify({"exists": False})

    exec_path = log.report_path.replace(".pdf", "_executive.pdf")
    return jsonify({"exists": os.path.exists(exec_path)})


@scheduler_bp.route('/confirm-scan/<token>')
def confirm_scan(token):
    """
    Public route for target owners to confirm a scheduled scan.
    """
    from models.scheduler_models import ScanConsentToken, IST
    from Services import scheduler_service
    from datetime import datetime
    
    consent = ScanConsentToken.query.filter_by(token=token).first()
    
    if not consent:
        return render_template('scheduler/consent_result.html', status='error', message='Invalid authorization token.')
        
    if consent.status == 'approved':
        return render_template('scheduler/consent_result.html', status='success', message='This scan has already been authorized.')
        
    if consent.is_expired():
        consent.status = 'expired'
        db.session.commit()
        return render_template('scheduler/consent_result.html', status='error', message='This authorization link has expired (1 hour limit).')

    # Simply approve the token — the scheduled job will run at its configured time
    # and will find this approved token, then proceed with the scan.
    consent.status = 'approved'
    consent.approved_at = datetime.now(IST).replace(tzinfo=None)
    db.session.commit()
    logger.info(f"[+] [scheduler_bp] Consent approved for job {consent.job_id} — scan will run at its scheduled time.")

    return render_template('scheduler/consent_result.html', status='success', message='Scan authorized! The security audit will begin at its next scheduled time.')

