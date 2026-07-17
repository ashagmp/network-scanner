from flask import Blueprint, render_template, request, jsonify
from app.scanner import run_scan

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target', '').strip()
    port_range = request.form.get('port_range', 'common')

    if not target:
        return jsonify({"error": "No target specified"})

    results = run_scan(target, port_range)
    return jsonify(results)
