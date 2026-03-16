import os
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required
from models import Client, Audit
from extensions import db

clients_bp = Blueprint("clients", __name__, url_prefix="/clients")


@clients_bp.route("/")
@login_required
def list_clients():
    clients = Client.query.order_by(Client.name).all()
    return render_template("clients/list.html", clients=clients)


@clients_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_client():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Client name is required.", "danger")
            return render_template("clients/new.html")
        client = Client(
            name=name,
            description=request.form.get("description", "").strip(),
            contact=request.form.get("contact", "").strip(),
        )
        db.session.add(client)
        db.session.commit()
        flash(f"Client '{name}' created.", "success")
        return redirect(url_for("clients.list_clients"))
    return render_template("clients/new.html")


@clients_bp.route("/<int:client_id>")
@login_required
def detail(client_id):
    client = Client.query.get_or_404(client_id)
    audits = Audit.query.filter_by(client_id=client_id).order_by(Audit.created_at.desc()).all()
    return render_template("clients/detail.html", client=client, audits=audits)


@clients_bp.route("/<int:client_id>/edit", methods=["GET", "POST"])
@login_required
def edit_client(client_id):
    client = Client.query.get_or_404(client_id)
    if request.method == "POST":
        client.name = request.form.get("name", client.name).strip()
        client.description = request.form.get("description", "").strip()
        client.contact = request.form.get("contact", "").strip()
        db.session.commit()
        flash("Client updated.", "success")
        return redirect(url_for("clients.detail", client_id=client_id))
    return render_template("clients/edit.html", client=client)


@clients_bp.route("/<int:client_id>/delete", methods=["POST"])
@login_required
def delete_client(client_id):
    import re
    import shutil
    from flask import current_app
    client = Client.query.get_or_404(client_id)
    name = client.name
    # Remove the client's upload directory from disk before DB cascade
    try:
        slug = re.sub(r'[\s_-]+', '_', re.sub(r'[^\w\s-]', '', name.strip().lower()))[:60] or 'unknown'
        client_dir = os.path.join(current_app.config["UPLOAD_FOLDER"], slug)
        if os.path.isdir(client_dir):
            shutil.rmtree(client_dir)
    except Exception:
        pass
    db.session.delete(client)
    db.session.commit()
    flash(f"Client '{name}' deleted.", "success")
    return redirect(url_for("clients.list_clients"))
