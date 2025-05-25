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
        return bayefalls

    for bayefall_name in os.listdir(logs_dir):
        bayefall_path = os.path.join(logs_dir, bayefall_name)
        log_file = os.path.join(bayefall_path, "log.json")
        
        if os.path.isfile(log_file):
            try:
                with open(log_file, 'r') as f:
                    logs = json.load(f)
                
                commands = {}
                operations = []
                
                for log in logs:
                    if log.get('type') == 'command':
                        cmd_data = log.get('data', {})
                        command_id = cmd_data.get('id')
                        if command_id:
                            commands[command_id] = {
                                'time': log.get('time'),
                                'command': cmd_data.get('command'),
                                'id': command_id,
                                'output': None,
                                'output_time': None
                            }
                    elif log.get('type') == 'output':
                        output_data = log.get('data', '')
                        command_id = None
                        
                        # Try to extract command ID from output
                        if 'id:' in output_data:
                            command_id = output_data.split('id:')[-1].strip()
                        
                        # Fallback to most recent command
                        if not command_id and commands:
                            command_id = next(iter(commands.keys()))
                        
                        if command_id in commands:
                            commands[command_id]['output'] = output_data
                            commands[command_id]['output_time'] = log.get('time')
                            operations.append(commands.pop(command_id))
                
                # Add any remaining unpaired commands
                operations.extend(commands.values())
                
                # Sort by time
                operations.sort(key=lambda x: x['time'])
                
                bayefalls.append({
                    'name': bayefall_name,
                    'operations': operations[-10:],  # Last 10 operations
                    'system_info': get_system_info(logs)
                })
                
            except Exception as e:
                print(f"Error loading {log_file}: {str(e)}")
    
    return bayefalls


def get_system_info(logs):
    """Extract system information from logs"""
    for log in logs:
        if log.get('type') == 'system_info':
            return log.get('data', {})
    return {}


def get_screenshots():
    """Get sorted screenshots with thumbnails"""
    screenshots = []
    ss_dir = CONFIG["PATHS"]["SCREENSHOTS_DIR"]
    
    if os.path.exists(ss_dir):
        for filename in sorted(os.listdir(ss_dir)):
            if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                screenshots.append({
                    'name': filename,
                    'path': os.path.join("Downloads", "screenshots", filename)
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
                        'path': os.path.join("Downloads", "exfiltrated_data", filename),
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
        'application/x-tar': 'file-zip',
    }
    
    for prefix, icon in type_map.items():
        if ftype.mime.startswith(prefix):
            return icon
    return 'file-earmark'


def generate_html_dashboard(bayefalls, screenshots, exfiltrated):
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
        .command-output {{
            max-height: 60vh;
            overflow-y: auto;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 4px;
            padding: 15px;
        }}
        .command-box {{
            background: rgba(255, 255, 255, 0.05);
            border-left: 3px solid {CONFIG['THEME']['PRIMARY']};
            padding: 10px;
            margin: 5px 0;
            font-family: 'Courier New', monospace;
        }}
        .output-box {{
            background: rgba(0, 0, 0, 0.3);
            padding: 10px;
            margin: 5px 0;
            white-space: pre-wrap;
        }}
        .time-badge {{
            font-size: 0.8em;
            background: {CONFIG['THEME']['SECONDARY']};
        }}
    </style>
</head>
<body>
    <div class="container py-4">
        <h1 class="text-center mb-4">{CONFIG['TITLE']}</h1>
        
        <!-- Active Agents -->
        <div class="row">
            <div class="col-md-8 mx-auto">
                <h4 class="mb-3">🖥️ Active Agents</h4>
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

    <!-- Agent Details Modal -->
    <div class="modal fade" id="bayefallModal">
        <div class="modal-dialog modal-xl">
            <div class="modal-content bg-dark">
                <div class="modal-header">
                    <h5 class="modal-title">Agent Details: <span id="agentName"></span></h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="agentDetailsContent"></div>
            </div>
        </div>
    </div>

    <!-- Screenshot Modal -->
    <div class="modal fade" id="screenshotModal">
        <div class="modal-dialog modal-fullscreen">
            <div class="modal-content bg-dark">
                <div class="modal-header">
                    <h5 class="modal-title" id="screenshotTitle"></h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body text-center">
                    <img id="screenshotFull" class="img-fluid" style="max-height: 90vh;" src="" alt="Full screenshot">
                </div>
                <div class="modal-footer">
                    <a id="screenshotDownload" href="#" class="btn btn-primary">
                        <i class="bi bi-download"></i> Download Original
                    </a>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        async function showBayefallDetails(agentName) {{
            try {{
                const response = await fetch(`/report/agent/${{agentName}}`);
                if (!response.ok) throw new Error(`HTTP error! status: ${{response.status}}`);
                
                const data = await response.json();
                
                const detailsHtml = `
                    <div class="timeline">
                        ${{data.operations.map(op => `
                            <div class="timeline-item">
                                <div class="timeline-header">
                                    <span class="time-badge badge bg-secondary">
                                        ${{formatTime(op.time)}}
                                    </span>
                                    <span class="badge bg-primary ms-2">ID: ${{op.id}}</span>
                                </div>
                                
                                <div class="command-box">
                                    ${{op.command || 'No command recorded'}}
                                </div>
                                
                                ${{op.output ? `
                                    <div class="output-box mt-2">
                                        <div class="text-muted small">
                                            Output received at ${{formatTime(op.output_time)}}
                                        </div>
                                        <pre class="mb-0">${{op.output}}</pre>
                                    </div>
                                ` : `
                                    <div class="text-muted small mt-1">
                                        No output received for this command
                                    </div>
                                `}}
                            </div>
                        `).join('')}}
                    </div>
                    
                    ${{data.system_info ? `
                        <div class="system-info mt-4">
                            <h5>System Information</h5>
                            <pre class="bg-black p-3 rounded">${{JSON.stringify(data.system_info, null, 2)}}</pre>
                        </div>
                    ` : ''}}
                `;

                document.getElementById('agentName').textContent = agentName;
                document.getElementById('agentDetailsContent').innerHTML = detailsHtml;
                new bootstrap.Modal('#bayefallModal').show();
            }} catch (error) {{
                console.error('Failed to load agent details:', error);
                alert('Failed to load agent details. Check console for details.');
            }}
        }}

        function formatTime(isoString) {{
            if (!isoString) return 'Unknown time';
            try {{
                const date = new Date(isoString);
                return date.toLocaleTimeString('en-US', {{
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                    hour12: false
                }});
            }} catch {{
                return isoString.split('T')[1]?.split('.')[0] || isoString;
            }}
        }}

        // Screenshot thumbnail click handler
        document.addEventListener('click', (e) => {{
            if (e.target.closest('.screenshot-thumb')) {{
                const thumb = e.target.closest('.screenshot-thumb');
                const fullPath = thumb.dataset.full;
                const fileName = thumb.querySelector('div').textContent;
                
                document.getElementById('screenshotFull').src = `/files/${{fullPath}}`;
                document.getElementById('screenshotDownload').href = `/report/download/${{fullPath}}`;
                document.getElementById('screenshotTitle').textContent = fileName;
            }}
        }});
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
    
    return '\n'.join([f"""
        <div class="col-6 col-md-4 col-lg-3">
            <div class="screenshot-thumb" 
                 data-bs-toggle="modal" 
                 data-bs-target="#screenshotModal"
                 data-full="{shot['path']}"
                 data-name="{shot['name']}">
                <img src="/files/{shot['path']}" 
                     class="img-fluid rounded"
                     loading="lazy">
                <div class="text-truncate small mt-1">{shot['name']}</div>
            </div>
        </div>
    """ for shot in screenshots])

def generate_exfiltrated_grid(exfiltrated):
    if not exfiltrated:
        return '<div class="text-muted">No exfiltrated data found</div>'
    
    return '\n'.join([f"""
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
                    <a href="/report/download/{item['path']}" class="btn btn-sm btn-outline-secondary w-100">
                        <i class="bi bi-download"></i> Download
                    </a>
                </div>
                <div class="card-footer text-muted small">
                    {item['mtime']} • {item['type']}
                </div>
            </div>
        </div>
    """ for item in exfiltrated])

def main():
    bayefalls = load_bayefalls()
    screenshots = get_screenshots()
    exfiltrated = get_exfiltrated_files()
    
    with open(CONFIG["PATHS"]["OUTPUT_HTML"], 'w', encoding='utf-8') as f:
        f.write(generate_html_dashboard(bayefalls, screenshots, exfiltrated))
    
    print(f"Report generated: {CONFIG['PATHS']['OUTPUT_HTML']}")

if __name__ == "__main__":
    main()
