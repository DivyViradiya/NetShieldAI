from flask import render_template, jsonify, request, Response, Blueprint, current_app, send_from_directory
from flask_login import login_required, current_user
import threading
import logging
import os
import re
from datetime import datetime, timezone
from werkzeug.utils import secure_filename

from core.extensions import db
from models.models import Asset, DomainInventory, User
from Services import asset_discovery_service
from Services import scan_logger, report_manager

logger = logging.getLogger(__name__)

asset_discovery_bp = Blueprint('asset_discovery_bp', __name__)


# ─── Helpers ────────────────────────────────────────────────────────────────

def get_user_identifier():
    """Returns a filesystem-safe user identifier for logging and results."""
    return f"{secure_filename(current_user.username)}_{current_user.id}"


def get_asset_results_dir():
    """Returns (and creates) the per-user asset_discovery results directory."""
    user_base_dir = report_manager.get_user_results_dir(current_user)
    user_dir = os.path.join(user_base_dir, 'asset_discovery')
    os.makedirs(user_dir, exist_ok=True)
    return user_dir


# ─── Page Render ────────────────────────────────────────────────────────────

@asset_discovery_bp.route('/')
@login_required
def dashboard():
    """Renders the Asset Discovery & Inventory dashboard."""
    logger.info(f"[*] Accessing Asset Discovery Dashboard (User: {current_user.username})")
    
    user_agent = request.headers.get('User-Agent')
    if user_agent and any(word in user_agent for word in ['Mobile', 'Android', 'iPhone', 'iPad']):
        return render_template('mobile_scanners/asset_discovery.html')
        
    return render_template('scanners/asset_discovery.html')


# ─── Dashboard Initialisation Data ──────────────────────────────────────────

@asset_discovery_bp.route('/init_data', methods=['GET'])
@login_required
def init_data():
    """Returns dashboard boot data: stats, latest discoveries, and scan state."""
    user_id = current_user.id

    total_assets = Asset.query.filter_by(user_id=user_id).count()
    subdomains   = Asset.query.filter_by(user_id=user_id, asset_type='subdomain').count()
    root_domains = Asset.query.filter_by(user_id=user_id, asset_type='domain').count()

    latest_assets = (Asset.query
                     .filter_by(user_id=user_id)
                     .order_by(Asset.created_at.desc())
                     .limit(5)
                     .all())

    return jsonify({
        "status": "success",
        "stats": {
            "total":     total_assets,
            "subdomains": subdomains,
            "domains":   root_domains,
        },
        "latest_discovery": [
            {"value": a.value, "type": a.asset_type,
             "created_at": a.created_at.isoformat()}
            for a in latest_assets
        ],
        "is_running": asset_discovery_service.is_scan_running(user_id),
    })


# ─── Scanning ────────────────────────────────────────────────────────────────

@asset_discovery_bp.route('/discover', methods=['POST'])
@login_required
def discover_assets():
    """Validates input and initiates a background asset discovery sweep."""
    data   = request.get_json() or {}
    domain = (data.get('domain') or '').strip().lower()

    if not domain:
        return jsonify({"status": "error", "message": "No domain provided."}), 400

    domain_regex = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if not re.match(domain_regex, domain):
        return jsonify({
            "status": "error",
            "message": f"Invalid domain format: '{domain}'. Use format: example.com"
        }), 400

    user_id         = current_user.id
    user_identifier = get_user_identifier()

    # Prevent concurrent scans
    if asset_discovery_service.is_scan_running(user_id):
        return jsonify({
            "status": "error",
            "message": "A discovery sweep is already in progress for this user."
        }), 409

    # Target Validation Guardrails
    user_confirmed_auth = bool(data.get('user_confirmed_auth', False))
    from Services.target_validator import validate_target, TargetBlockedError, AuthorizationRequiredError
    try:
        validate_target(domain, user_confirmed_auth=user_confirmed_auth)
    except TargetBlockedError as e:
        return jsonify({"status": "blocked", "message": f"Scan Prohibited: {str(e)}"}), 403
    except AuthorizationRequiredError as e:
        return jsonify({"status": "auth_required", "message": str(e)}), 403

    # Reset SSE log for this session
    scan_logger.reset_log_file(user_identifier, "asset_discovery")

    # Capture app context for background thread
    app = current_app._get_current_object()

    def run_discovery():
        with app.app_context():
            try:
                asset_discovery_service.start_asset_discovery(domain, user_id, user_identifier)
            except Exception as e:
                logger.error(f"[!] Asset Discovery Critical Failure: {e}")
                asset_discovery_service.log(user_identifier, f"[!] Critical Error: {e}", level='ERROR')

    threading.Thread(target=run_discovery, daemon=True).start()

    return jsonify({
        "status":  "success",
        "message": f"Discovery sweep for '{domain}' initiated in background.",
        "target":  domain,
    })


# ─── Asset Inventory ─────────────────────────────────────────────────────────

@asset_discovery_bp.route('/assets', methods=['GET'])
@login_required
def get_assets():
    """Returns the full enriched asset inventory for the current user."""
    user_id   = current_user.id
    asset_type_filter = request.args.get('type')      # optional: domain / subdomain
    bv_filter         = request.args.get('business_value')  # optional: High / Medium / Low

    query = Asset.query.filter_by(user_id=user_id)
    if asset_type_filter:
        query = query.filter_by(asset_type=asset_type_filter)
    if bv_filter:
        query = query.filter_by(business_value=bv_filter)

    assets = query.order_by(Asset.criticality_score.desc()).all()

    inventory_list = []
    for asset in assets:
        inv = asset.inventory
        tech  = dict(inv.tech_stack) if inv and inv.tech_stack else {}

        # Separate internal hidden keys from display tech stack
        tech_display = {k: v for k, v in tech.items()
                        if k not in ('cloud_assets', 'ssl_detail')}
        ssl_detail   = tech.get('ssl_detail', {})
        cloud        = tech.get('cloud_assets', [])

        entry = {
            "id":               asset.id,
            "value":            asset.value,
            "type":             asset.asset_type,
            "business_value":   asset.business_value or 'Medium',
            "discovery_method": asset.discovery_method,
            "criticality":      asset.criticality_score,
            "last_seen":        asset.last_seen.isoformat() if asset.last_seen else None,
            "details":          None,
        }

        if inv:
            entry["details"] = {
                "registrar":   inv.registrar,
                "created":     inv.creation_date.isoformat() if inv.creation_date else None,
                "expires":     inv.expiry_date.isoformat()   if inv.expiry_date   else None,
                "ip":          inv.resolved_ip,
                "asn":         inv.asn_info,
                "tech":        tech_display,
                "dns":         inv.dns_records,
                "ssl": {
                    "status":         inv.ssl_status,
                    "expiry_date":    ssl_detail.get('expiry_date'),
                    "issuer":         ssl_detail.get('issuer'),
                    "days_remaining": ssl_detail.get('days_remaining'),
                },
                "mail_posture":  inv.email_posture,
                "cloud_exposure": cloud or None,
            }
        inventory_list.append(entry)

    return jsonify({
        "status": "success",
        "count":  len(inventory_list),
        "assets": inventory_list,
    })


# ─── SSE Log Stream ──────────────────────────────────────────────────────────

@asset_discovery_bp.route('/log_stream')
@login_required
def log_stream():
    """Streams live discovery logs to the frontend via Server-Sent Events."""
    user_identifier = get_user_identifier()
    return Response(
        scan_logger.tail_log_file(user_identifier, "asset_discovery"),
        mimetype='text/event-stream'
    )


# ─── Reports & Downloads ─────────────────────────────────────────────────────

@asset_discovery_bp.route('/download_pdf', methods=['GET'])
@login_required
def download_pdf():
    """Serves the latest Asset Discovery PDF report."""
    target   = request.args.get('target')
    user_dir = get_asset_results_dir()

    report_path = report_manager.find_latest_report(user_dir, "asset_discovery", target=target)
    if not report_path or not os.path.exists(report_path):
        return jsonify({"status": "error", "message": "PDF report not found."}), 404

    return send_from_directory(
        directory=os.path.dirname(report_path),
        path=os.path.basename(report_path),
        as_attachment=True
    )


@asset_discovery_bp.route('/get_json_report', methods=['GET'])
@login_required
def get_json_report():
    """Serves the latest Asset Discovery JSON report."""
    target   = request.args.get('target')
    user_dir = get_asset_results_dir()

    report_path = report_manager.find_latest_report(
        user_dir, "asset_discovery", target=target, extension="json")
    if not report_path or not os.path.exists(report_path):
        return jsonify({"status": "error", "message": "JSON report not found."}), 404

    return send_from_directory(
        directory=os.path.dirname(report_path),
        path=os.path.basename(report_path),
        as_attachment=True
    )


@asset_discovery_bp.route('/report_history', methods=['GET'])
@login_required
def get_report_history():
    """Returns the scan history list for the asset discovery module."""
    user_dir = get_asset_results_dir()
    history  = report_manager.get_report_history(user_dir, scanner_name="asset_discovery")
    return jsonify({"status": "success", "history": history})


# ─── Intelligence Digest Endpoints ───────────────────────────────────────────

@asset_discovery_bp.route('/ssl_digest', methods=['GET'])
@login_required
def ssl_digest():
    """
    Returns a summary of SSL certificate posture across all assets.
    Groups assets by: Valid, Expiring Soon, Expired, No SSL.
    """
    user_id = current_user.id
    assets  = (Asset.query.filter_by(user_id=user_id)
               .join(DomainInventory, DomainInventory.asset_id == Asset.id, isouter=True)
               .all())

    groups  = {"Valid": [], "Expiring Soon": [], "Expired": [], "No SSL": [], "Unknown": []}
    for asset in assets:
        inv    = asset.inventory
        status = (inv.ssl_status if inv and inv.ssl_status else "Unknown")
        bucket = groups.get(status, groups["Unknown"])
        tech   = dict(inv.tech_stack) if inv and inv.tech_stack else {}
        ssl_d  = tech.get('ssl_detail', {})
        bucket.append({
            "value":         asset.value,
            "type":          asset.asset_type,
            "days_remaining": ssl_d.get('days_remaining'),
            "expiry_date":   ssl_d.get('expiry_date'),
            "issuer":        ssl_d.get('issuer'),
        })

    return jsonify({
        "status": "success",
        "counts": {k: len(v) for k, v in groups.items()},
        "groups": groups,
    })


@asset_discovery_bp.route('/mail_posture_summary', methods=['GET'])
@login_required
def mail_posture_summary():
    """
    Aggregates SPF / DMARC / DKIM pass rates across all domain assets.
    """
    user_id = current_user.id
    domains = (Asset.query
               .filter_by(user_id=user_id, asset_type='domain')
               .join(DomainInventory, DomainInventory.asset_id == Asset.id, isouter=True)
               .all())

    spf_pass = dmarc_pass = dkim_pass = 0
    details  = []
    for asset in domains:
        inv  = asset.inventory
        mail = inv.email_posture if inv and inv.email_posture else {}
        spf   = bool(mail.get('spf'))
        dmarc = bool(mail.get('dmarc'))
        dkim  = bool(mail.get('dkim'))

        if spf:   spf_pass   += 1
        if dmarc: dmarc_pass += 1
        if dkim:  dkim_pass  += 1

        details.append({
            "domain": asset.value,
            "spf":    spf,
            "dmarc":  dmarc,
            "dkim":   dkim,
            "mx_count": mail.get('mx_count', 0),
        })

    total = len(domains)
    return jsonify({
        "status":     "success",
        "total":      total,
        "spf_pass":   spf_pass,
        "dmarc_pass": dmarc_pass,
        "dkim_pass":  dkim_pass,
        "details":    details,
    })


@asset_discovery_bp.route('/cloud_exposure', methods=['GET'])
@login_required
def cloud_exposure():
    """Returns all assets where cloud storage exposure was detected."""
    user_id = current_user.id
    assets  = (Asset.query.filter_by(user_id=user_id)
               .join(DomainInventory, DomainInventory.asset_id == Asset.id, isouter=True)
               .all())

    exposed = []
    for asset in assets:
        inv  = asset.inventory
        if not inv or not inv.tech_stack:
            continue
        cloud = inv.tech_stack.get('cloud_assets', [])
        if cloud:
            exposed.append({
                "value":     asset.value,
                "type":      asset.asset_type,
                "exposures": cloud,
            })

    return jsonify({
        "status":  "success",
        "total":   len(exposed),
        "exposed": exposed,
    })


# ─── AI Executive Summary ─────────────────────────────────────────────────────

@asset_discovery_bp.route('/trigger_executive_summary', methods=['POST'])
@login_required
def trigger_executive_summary():
    """Triggers AI executive summary generation for the latest asset discovery scan."""
    data            = request.get_json() or {}
    target          = data.get('target')
    user_id         = current_user.id
    user_identifier = get_user_identifier()
    user_dir        = get_asset_results_dir()

    # Resolve technical report
    report_path = report_manager.find_latest_report(user_dir, "asset_discovery", target=target)
    if not report_path:
        return jsonify({"status": "error", "message": "Technical report not found."}), 404

    # Find the matching completed scan log
    from models.models import ScanLog
    latest_log = (ScanLog.query
                  .filter_by(user_id=user_id, tool_name="asset_discovery", status="Completed")
                  .order_by(ScanLog.start_time.desc())
                  .first())
    if not latest_log:
        return jsonify({"status": "error", "message": "No completed scan found for summary."}), 404

    from Services import ai_report_service
    success, result = ai_report_service.generate_executive_summary(
        log_id=latest_log.id,
        user_identifier=user_identifier,
        report_path=report_path,
        target=target,
        tool_name="Asset Discovery & Inventory"
    )

    if success:
        return jsonify({
            "status":       "success",
            "message":      "AI Summary generated.",
            "download_url": f"/asset_discovery/download_pdf?target={target}&type=executive",
        })
    return jsonify({"status": "error", "message": result}), 500
