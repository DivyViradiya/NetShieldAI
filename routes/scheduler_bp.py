"""
Scheduler Blueprint
===================
Full CRUD API + UI page for managing scan profiles, configs, targets,
recipients, and scheduled jobs.
"""

import json
from datetime import datetime

from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user

from core.logger_setup import logger
from core.extensions import db
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

    profile.updated_at = datetime.utcnow()
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
    profile.updated_at = datetime.utcnow()
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

    profile.updated_at = datetime.utcnow()
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
    profile.updated_at = datetime.utcnow()
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

    target = ProfileTarget(profile_id=profile.id, target_url=target_url)
    db.session.add(target)
    profile.updated_at = datetime.utcnow()
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
    profile.updated_at = datetime.utcnow()
    db.session.commit()

    return jsonify({"status": "success", "message": "Target removed."})


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
    profile.updated_at = datetime.utcnow()
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
    profile.updated_at = datetime.utcnow()
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
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "Invalid one_shot_at format. Use ISO format."}), 400

    if schedule_type == 'weekly' and not cron_day_of_week:
        return jsonify({"status": "error", "message": "cron_day_of_week is required for weekly scheduling."}), 400

    if schedule_type == 'monthly':
        if cron_day_of_month is None:
            return jsonify({"status": "error", "message": "cron_day_of_month is required for monthly scheduling."}), 400
        cron_day_of_month = int(cron_day_of_month)

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
        is_enabled=True
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
    """Get past runs for a job — queries ScanLog from the primary DB."""
    job = db.session.get(ScheduledScanJob, job_id)
    if not job:
        return jsonify({"status": "error", "message": "Job not found."}), 404

    profile, err = _get_profile_or_404(job.profile_id)
    if err:
        return err

    # Query ScanLog from primary DB for this user's scans
    from models.models import ScanLog
    logs = ScanLog.query.filter_by(user_id=current_user.id)\
        .order_by(ScanLog.start_time.desc())\
        .limit(20).all()

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
