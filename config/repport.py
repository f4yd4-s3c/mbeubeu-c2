import json
from datetime import datetime

# Load JSON from db.json
with open('db.json', 'r') as file:
    data = json.load(file)

html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Red Team Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            padding: 20px;
        }}
        h1 {{
            color: #333;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            background-color: #fff;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }}
        th {{
            background-color: #333;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .online {{
            color: green;
            font-weight: bold;
        }}
        .offline {{
            color: red;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <h1>Red Team Operation Report</h1>

    <div class="section">
        <h2>Agents</h2>
        <table>
            <tr>
                <th>ID</th>
                <th>Last Seen</th>
                <th>Status</th>
                <th>Listener URL</th>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>Username</th>
            </tr>
            {agents_rows}
        </table>
    </div>

    <div class="section">
        <h2>Listeners</h2>
        <table>
            <tr>
                <th>Name</th>
                <th>Address</th>
                <th>Type</th>
                <th>Active</th>
            </tr>
            {listeners_rows}
        </table>
    </div>
</body>
</html>
"""

# Generate agents rows
agents_rows = ""
for agent_id, agent in data["agents"].items():
    status_class = "online" if agent["status"] == "ONLINE" else "offline"
    last_seen_fmt = datetime.fromisoformat(agent["last_seen"]).strftime('%Y-%m-%d %H:%M:%S')
    agents_rows += f"""
    <tr>
        <td>{agent_id}</td>
        <td>{last_seen_fmt}</td>
        <td class="{status_class}">{agent['status']}</td>
        <td>{agent['listener_url']}</td>
        <td>{agent['info']['ip_address']}</td>
        <td>{agent['info']['hostname']}</td>
        <td>{agent['info']['username']}</td>
    </tr>
    """

# Generate listeners rows
listeners_rows = ""
for listener_id, listener in data["listeners"].items():
    active_status = "Yes" if listener["active"] else "No"
    listeners_rows += f"""
    <tr>
        <td>{listener['name']}</td>
        <td>{listener['address']}</td>
        <td>{listener['type']}</td>
        <td>{active_status}</td>
    </tr>
    """

# Render final HTML
html_output = html_template.format(agents_rows=agents_rows, listeners_rows=listeners_rows)

# Write to file
with open("redteam_report.html", "w") as report_file:
    report_file.write(html_output)

print("✅ Report generated: redteam_report.html")

