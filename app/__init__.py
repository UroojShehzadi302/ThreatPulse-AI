import os
import sys
import json
import threading
from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify, send_file
from werkzeug.utils import secure_filename
from config import Config
from ai_engine.predict import predict_data 
from live_monitor.capture import monitor_instance
from live_monitor.simulator import run_demo_attack
from reports.generator import generate_evaluation_report

def create_app():
    app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')
    app.config.from_object(Config)
    app.config['SECRET_KEY'] = 'threatpulse_super_secret_key' 
    
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'datasets')
    app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024 

    @app.route('/')
    def home():
        metrics_path = os.path.join(BASE_DIR, 'frontend', 'static', 'training_metrics.json')
        metrics_data = {}
        if os.path.exists(metrics_path):
            with open(metrics_path, 'r') as f:
                metrics_data = json.load(f)

        pdc_path = os.path.join(BASE_DIR, 'pdc', 'results.json')
        pdc_data = {}
        if os.path.exists(pdc_path):
            with open(pdc_path, 'r') as f:
                pdc_data = json.load(f)

        live_packets = monitor_instance.packet_count

        return render_template('dashboard.html', metrics=metrics_data, pdc=pdc_data, live_packets=live_packets)

    @app.route('/readiness')
    def readiness():
        py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        model_path = os.path.join(BASE_DIR, 'models', 'random_forest_model.pkl')
        model_exists = os.path.exists(model_path)
        return render_template('readiness.html', python_version=py_version, model_status=model_exists)

    @app.route('/analysis', methods=['GET', 'POST'])
    def analysis():
        results = None
        if request.method == 'POST':
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
                
            if file:
                filename = secure_filename(file.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                try:
                    results = predict_data(filepath)
                    session['latest_results'] = results 
                except Exception as e:
                    flash(f"Error processing file: {str(e)}")
                    return redirect(request.url)

        return render_template('analysis.html', results=results)

    @app.route('/evaluation')
    def evaluation():
        metrics_path = os.path.join(BASE_DIR, 'frontend', 'static', 'training_metrics.json')
        metrics_data = None
        if os.path.exists(metrics_path):
            with open(metrics_path, 'r') as f:
                metrics_data = json.load(f)
                
        dynamic_results = session.get('latest_results', None)
        return render_template('evaluation.html', metrics=metrics_data, results=dynamic_results)

    @app.route('/download_report')
    def download_report():
        metrics_path = os.path.join(BASE_DIR, 'frontend', 'static', 'training_metrics.json')
        metrics_data = None
        if os.path.exists(metrics_path):
            with open(metrics_path, 'r') as f:
                metrics_data = json.load(f)

        reports_dir = os.path.join(BASE_DIR, 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        pdf_filename = 'ThreatPulse_Evaluation_Report.pdf'
        pdf_path = os.path.join(reports_dir, pdf_filename)
        
        generate_evaluation_report(metrics_data, pdf_path)
        return send_file(pdf_path, as_attachment=True)

    @app.route('/performance')
    def performance():
        results_path = os.path.join(BASE_DIR, 'pdc', 'results.json')
        perf_data = None
        
        if os.path.exists(results_path):
            with open(results_path, 'r') as f:
                perf_data = json.load(f)
                
        return render_template('performance.html', perf=perf_data)

    # --- LIVE MONITOR ROUTES ---
    @app.route('/live-monitor')
    def live_monitor():
        return render_template('live_monitor.html')

    @app.route('/api/start_capture', methods=['POST'])
    def start_capture():
        monitor_instance.start()
        return jsonify({"status": "success", "message": "Capture started"})

    @app.route('/api/stop_capture', methods=['POST'])
    def stop_capture():
        monitor_instance.stop()
        return jsonify({"status": "success", "message": "Capture stopped"})

    @app.route('/api/capture_status')
    def capture_status():
        return jsonify({
            "is_running": monitor_instance.is_running,
            "packet_count": monitor_instance.packet_count,
            "recent_packets": monitor_instance.recent_packets
        })

    @app.route('/api/run_demo_attack', methods=['POST'])
    def trigger_demo():
        threading.Thread(target=run_demo_attack).start()
        return jsonify({"status": "success", "message": "Demo attack started!"})

    return app