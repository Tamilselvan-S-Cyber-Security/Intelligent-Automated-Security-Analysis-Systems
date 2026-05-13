import os
import json
import logging
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from jinja2 import Environment, FileSystemLoader
from PIL import Image, ImageDraw, ImageFont
import base64
from io import BytesIO
import matplotlib.pyplot as plt
import seaborn as sns

# Reduce noisy Kaleido/Choreographer logs during image export
logging.getLogger("kaleido").setLevel(logging.WARNING)
logging.getLogger("choreographer").setLevel(logging.WARNING)

class ReportGenerator:
    def __init__(self, results: dict, url: str):
        self.results = results
        self.url = url
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(loader=FileSystemLoader(self.template_dir))
        
    def generate_reports(self):
        """Generate both HTML and PDF reports"""
        html_report = self._generate_html_report()
        return html_report
    
    def _generate_html_report(self):
        """Generate HTML report with visualizations"""
        template = self.env.get_template('report_template.html')
        
        # Generate visualizations
        visualizations = self._generate_visualizations()
        
        # Prepare data for template
        report_data = {
            'url': self.url,
            'timestamp': self.timestamp,
            'security_score': self._calculate_security_score(),
            'issues': self._process_issues(),
            'visualizations': visualizations,
            'watermark': self._generate_watermark()
        }
        
        return template.render(report_data)
    
    def _generate_visualizations(self):
        """Generate various visualizations for the report"""
        visualizations = {}
        
        # Security Score Gauge
        try:
            score = self._calculate_security_score()
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Security Score"},
                gauge={'axis': {'range': [0, 100]},
                      'bar': {'color': self._get_score_color(score)},
                      'steps': [
                          {'range': [0, 40], 'color': "red"},
                          {'range': [40, 70], 'color': "yellow"},
                          {'range': [70, 100], 'color': "green"}
                      ]}
            ))
            visualizations['score_gauge'] = self._fig_to_base64(fig)
        except Exception as e:
            print(f"Warning: Failed to generate score gauge: {e}")
            visualizations['score_gauge'] = ""
        
        # Issue Distribution
        try:
            issues_df = pd.DataFrame(self._process_issues())
            if not issues_df.empty:
                fig = px.pie(issues_df, names='priority', title='Issue Distribution by Priority')
                visualizations['issue_distribution'] = self._fig_to_base64(fig)
                
                # Issue Timeline - Count occurrences of each category
                # Using to_frame() for better compatibility across pandas versions
                category_counts = issues_df['category'].value_counts().to_frame('count').reset_index()
                category_counts.columns = ['category', 'count']
                fig = px.bar(category_counts, x='category', y='count', title='Issues by Category')
                visualizations['issue_timeline'] = self._fig_to_base64(fig)
        except Exception as e:
            print(f"Warning: Failed to generate issue charts: {e}")
            visualizations['issue_distribution'] = ""
            visualizations['issue_timeline'] = ""
        
        # Security Headers Heatmap
        try:
            headers_data = self._get_headers_data()
            if headers_data:
                plt.figure(figsize=(10, 6))
                sns.heatmap(pd.DataFrame(headers_data), annot=True, cmap='YlOrRd')
                visualizations['headers_heatmap'] = self._plt_to_base64()
        except Exception as e:
            print(f"Warning: Failed to generate headers heatmap: {e}")
            visualizations['headers_heatmap'] = ""
        
        return visualizations
    
    def _process_issues(self):
        """Process and categorize issues"""
        issues = []
        for result in self.results:
            for issue in result.get('issues', []):
                issues.append({
                    'title': issue['title'],
                    'description': issue['description'],
                    'priority': issue['priority'],
                    'recommendation': issue['recommendation'],
                    'category': result['scan_type']
                })
        return issues
    
    def _calculate_security_score(self):
        """Calculate overall security score"""
        total_issues = sum(len(r.get('issues', [])) for r in self.results)
        critical_issues = sum(1 for r in self.results for issue in r.get('issues', [])
                            if issue.get('priority') == 'Critical')
        return max(0, 100 - (critical_issues * 20) - (total_issues * 5))
    
    def _get_score_color(self, score):
        """Get color based on security score"""
        if score < 40:
            return "red"
        elif score < 70:
            return "yellow"
        return "green"
    
    def _get_headers_data(self):
        """Extract and process headers data"""
        headers_data = []
        for result in self.results:
            if 'headers' in result:
                headers_data.append({
                    'header': result['scan_type'],
                    'status': 'Present' if result.get('issues', []) else 'Missing'
                })
        return headers_data
    
    def _generate_watermark(self):
        """Generate watermark for reports"""
        try:
            watermark = Image.new('RGBA', (300, 100), (255, 255, 255, 0))
            draw = ImageDraw.Draw(watermark)
            try:
                font = ImageFont.truetype("arial.ttf", 16)
            except:
                font = ImageFont.load_default()
            draw.text((10, 40), "SKP Engineering College", font=font, fill=(128, 128, 128, 128))
            return self._image_to_base64(watermark)
        except Exception as e:
            # Return empty image if watermark generation fails
            return ""
    
    def _fig_to_base64(self, fig):
        """Convert Plotly figure to base64"""
        try:
            # Try using to_image with kaleido
            img_bytes = fig.to_image(format="png")
            return f"data:image/png;base64,{base64.b64encode(img_bytes).decode()}"
        except Exception as e:
            # Fallback: use write_image with BytesIO
            try:
                buf = BytesIO()
                fig.write_image(buf, format="png")
                buf.seek(0)
                return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"
            except Exception as e2:
                # Final fallback: return HTML version as data URI
                try:
                    html_str = fig.to_html(include_plotlyjs='cdn', config={'displayModeBar': False})
                    return f"data:text/html;base64,{base64.b64encode(html_str.encode()).decode()}"
                except:
                    # Return empty image if all methods fail
                    return ""
    
    def _plt_to_base64(self):
        """Convert Matplotlib plot to base64"""
        buf = BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        plt.close()
        return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"
    
    def _image_to_base64(self, image):
        """Convert PIL image to base64"""
        buf = BytesIO()
        image.save(buf, format='PNG')
        return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"

# HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Analysis Report - {{ url }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .report-container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            position: relative;
        }
        .watermark {
            position: absolute;
            opacity: 0.1;
            z-index: 1;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #eee;
        }
        .score-section {
            text-align: center;
            margin: 20px 0;
        }
        .visualization {
            margin: 20px 0;
            text-align: center;
        }
        .issues-section {
            margin-top: 30px;
        }
        .issue-card {
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
        }
        .critical { border-left: 5px solid red; }
        .high { border-left: 5px solid orange; }
        .medium { border-left: 5px solid yellow; }
        .low { border-left: 5px solid green; }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 2px solid #eee;
            font-size: 12px;
            color: #666;
        }
        @media print {
            body {
                background: white;
                padding: 0;
            }
            .report-container {
                box-shadow: none;
                padding: 0;
            }
            .visualization img {
                max-width: 100%;
                page-break-inside: avoid;
            }
            .issue-card {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="report-container">
        <img src="{{ watermark }}" class="watermark" style="top: 50%; left: 50%; transform: translate(-50%, -50%);">
        
        <div class="header">
            <h1>Intelligent Automated Security Analysis System</h1>
            <h2>Security Analysis Report</h2>
            <p><small>Developed by Security Team - SKP Engineering College, CSE 4th Year</small></p>
            <p>URL: {{ url }}</p>
            <p>Generated: {{ timestamp }}</p>
        </div>
        
        <div class="score-section">
            <h2>Security Score</h2>
            <img src="{{ visualizations.score_gauge }}" style="max-width: 500px;">
        </div>
        
        <div class="visualization">
            <h2>Issue Distribution</h2>
            <img src="{{ visualizations.issue_distribution }}" style="max-width: 600px;">
        </div>
        
        <div class="visualization">
            <h2>Issues by Category</h2>
            <img src="{{ visualizations.issue_timeline }}" style="max-width: 600px;">
        </div>
        
        <div class="visualization">
            <h2>Security Headers Status</h2>
            <img src="{{ visualizations.headers_heatmap }}" style="max-width: 600px;">
        </div>
        
        <div class="issues-section">
            <h2>Detailed Findings</h2>
            {% for issue in issues %}
            <div class="issue-card {{ issue.priority.lower() }}">
                <h3>{{ issue.title }}</h3>
                <p><strong>Priority:</strong> {{ issue.priority }}</p>
                <p><strong>Category:</strong> {{ issue.category }}</p>
                <p><strong>Description:</strong> {{ issue.description }}</p>
                <p><strong>Recommendation:</strong> {{ issue.recommendation }}</p>
            </div>
            {% endfor %}
        </div>
        
        <div class="footer">
            <p>Generated by Intelligent Automated Security Analysis System</p>
            <p>Developed by Security Team - SKP Engineering College, CSE 4th Year | Final Year Project</p>
            <p>&copy; {{ timestamp[:4] }} All rights reserved.</p>
        </div>
    </div>
</body>
</html>
"""

# Create templates directory if it doesn't exist
os.makedirs('templates', exist_ok=True)

# Save HTML template
with open('templates/report_template.html', 'w') as f:
    f.write(HTML_TEMPLATE) 