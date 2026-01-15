"""
MCP Server for Autonomous IP Security Decision Making
Complete Full Implementation
Integrates with SIEM systems to provide AI-powered threat analysis
Updated for new Google Genai API
"""

import pandas as pd
import json
from google import genai
from google.genai import types
from datetime import datetime
from typing import Dict, List, Any
import logging
from collections import defaultdict
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MCPSecurityServer:
    """
    Model Context Protocol Server for Security Event Analysis
    Analyzes security events and makes autonomous block/accept decisions
    """
    
    def __init__(self, excel_file: str, gemini_api_key: str):
        """Initialize the MCP server with data source and AI model"""
        self.excel_file = excel_file
        self.data = None
        self.ip_context = defaultdict(list)
        
        # Configure Gemini AI with new API
        self.client = genai.Client(api_key=gemini_api_key)
        
        logger.info("MCP Security Server initialized")
    
    def load_data(self) -> bool:
        """Load and parse security event data from Excel"""
        try:
            self.data = pd.read_excel(self.excel_file)
            logger.info(f"Loaded {len(self.data)} security events from {self.excel_file}")
            self._build_ip_context()
            return True
        except Exception as e:
            logger.error(f"Error loading data: {str(e)}")
            return False
    
    def _build_ip_context(self):
        """Build contextual information for each IP address"""
        for _, row in self.data.iterrows():
            attacker_ip = row['Attacker Address']
            self.ip_context[attacker_ip].append({
                'timestamp': str(row['TimeStamp']),
                'threat_type': row['Name'],
                'country': row['source Geo Country Name'],
                'outcome': row['CategoryOutcome'],
                'action': row['Device Action'],
                'port': int(row['Target Port']),
                'event_count': int(row['Aggregated Event Count'])
            })
        logger.info(f"Built context for {len(self.ip_context)} unique IP addresses")
    
    def get_ip_context(self, ip_address: str) -> Dict[str, Any]:
        """Retrieve comprehensive context for an IP address"""
        if ip_address not in self.ip_context:
            return {
                'ip': ip_address,
                'history': [],
                'total_events': 0,
                'risk_indicators': {}
            }
        
        events = self.ip_context[ip_address]
        
        # Calculate risk indicators
        blocked_attempts = sum(1 for e in events if str(e['action']).lower() in ['block', 'drop', 'denied'])
        failed_attempts = sum(1 for e in events if '/Failure' in str(e['outcome']))
        
        risk_indicators = {
            'total_events': len(events),
            'blocked_attempts': blocked_attempts,
            'failed_attempts': failed_attempts,
            'threat_types': list(set(e['threat_type'] for e in events)),
            'countries': list(set(e['country'] for e in events)),
            'targeted_ports': list(set(e['port'] for e in events)),
            'latest_activity': events[-1]['timestamp'] if events else None
        }
        
        return {
            'ip': ip_address,
            'history': events[-10:],  # Last 10 events
            'total_events': len(events),
            'risk_indicators': risk_indicators
        }
    
    def analyze_with_ai(self, ip_context: Dict[str, Any]) -> Dict[str, Any]:
        """Use Gemini AI to analyze IP context and make decision"""
        
        # Prepare prompt for AI analysis
        prompt = f"""You are a cybersecurity AI assistant analyzing network traffic. Based on the following IP address context, determine if this IP should be BLOCKED or ACCEPTED.

IP Address: {ip_context['ip']}
Total Events: {ip_context['total_events']}

Risk Indicators:
- Blocked Attempts: {ip_context['risk_indicators'].get('blocked_attempts', 0)}
- Failed Attempts: {ip_context['risk_indicators'].get('failed_attempts', 0)}
- Threat Types: {', '.join(ip_context['risk_indicators'].get('threat_types', [])[:3])}
- Source Countries: {', '.join(ip_context['risk_indicators'].get('countries', []))}
- Targeted Ports: {ip_context['risk_indicators'].get('targeted_ports', [])}
- Latest Activity: {ip_context['risk_indicators'].get('latest_activity', 'N/A')}

Recent Event History (last 3 events):
{json.dumps(ip_context['history'][-3:], indent=2)}

Analyze this data and provide your response ONLY as a valid JSON object with these exact fields:
{{
    "decision": "BLOCK or ACCEPT",
    "confidence": "High or Medium or Low",
    "reasoning": "your reasoning here in 1-2 sentences",
    "risk_score": 0-100
}}

Do not include any markdown formatting, backticks, or additional text. Only return the JSON object."""
        
        try:
            # Use new Gemini API
            response = self.client.models.generate_content(
                model='gemini-2.0-flash-exp',
                contents=prompt
            )
            
            result_text = response.text.strip()
            
            # Clean up the response
            if '```json' in result_text:
                result_text = result_text.split('```json')[1].split('```')[0].strip()
            elif '```' in result_text:
                result_text = result_text.split('```')[1].split('```')[0].strip()
            
            # Remove any remaining markdown or extra characters
            result_text = result_text.replace('```', '').strip()
            
            analysis = json.loads(result_text)
            
            # Validate required fields
            required_fields = ['decision', 'confidence', 'reasoning', 'risk_score']
            if not all(field in analysis for field in required_fields):
                raise ValueError("Missing required fields in AI response")
            
            # Ensure decision is uppercase
            analysis['decision'] = analysis['decision'].upper()
            
            logger.info(f"AI Analysis for {ip_context['ip']}: {analysis['decision']} (Confidence: {analysis['confidence']})")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error in AI analysis: {str(e)}")
            # Fallback to rule-based decision
            return self._fallback_decision(ip_context)
    
    def _fallback_decision(self, ip_context: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based fallback decision if AI fails"""
        risk_score = 0
        
        # Calculate risk based on indicators
        blocked = ip_context['risk_indicators'].get('blocked_attempts', 0)
        failed = ip_context['risk_indicators'].get('failed_attempts', 0)
        total = ip_context['total_events']
        
        if total > 0:
            # Weighted calculation
            block_rate = (blocked / total) * 100
            fail_rate = (failed / total) * 100
            risk_score = (block_rate * 0.6 + fail_rate * 0.4)
        
        decision = "BLOCK" if risk_score > 50 else "ACCEPT"
        
        if risk_score > 75 or risk_score < 25:
            confidence = "High"
        elif risk_score > 60 or risk_score < 40:
            confidence = "Medium"
        else:
            confidence = "Low"
        
        reasoning = f"Rule-based decision: {blocked} blocked attempts and {failed} failed attempts out of {total} total events. Block rate: {(blocked/total*100 if total > 0 else 0):.1f}%. Failed rate: {(failed/total*100 if total > 0 else 0):.1f}%."
        
        return {
            "decision": decision,
            "confidence": confidence,
            "reasoning": reasoning,
            "risk_score": int(risk_score)
        }
    
    def process_ip(self, ip_address: str) -> Dict[str, Any]:
        """Main method to process an IP and make decision"""
        logger.info(f"Processing IP: {ip_address}")
        
        # Get context
        context = self.get_ip_context(ip_address)
        
        # Analyze with AI
        decision = self.analyze_with_ai(context)
        
        # Prepare final response
        response = {
            'ip_address': ip_address,
            'timestamp': datetime.now().isoformat(),
            'context': {
                'total_events': context['total_events'],
                'risk_indicators': context['risk_indicators']
            },
            'decision': decision['decision'],
            'confidence': decision['confidence'],
            'reasoning': decision['reasoning'],
            'risk_score': decision['risk_score'],
            'recommendation': self._generate_recommendation(decision)
        }
        
        return response
    
    def _generate_recommendation(self, decision: Dict[str, Any]) -> str:
        """Generate actionable recommendation based on decision"""
        if decision['decision'] == 'BLOCK':
            if decision['confidence'] == 'High':
                return "Immediately block IP at firewall level. Add to permanent blacklist."
            elif decision['confidence'] == 'Medium':
                return "Block IP temporarily. Monitor for 24 hours before permanent action."
            else:
                return "Add IP to watchlist. Enable enhanced logging for this source."
        else:
            if decision['confidence'] == 'High':
                return "Accept traffic. IP shows legitimate behavior patterns."
            elif decision['confidence'] == 'Medium':
                return "Accept but monitor. Enable rate limiting for this IP."
            else:
                return "Accept with caution. Review manually if patterns change."
    
    def batch_process(self, ip_list: List[str]) -> List[Dict[str, Any]]:
        """Process multiple IPs in batch"""
        results = []
        logger.info(f"Starting batch processing of {len(ip_list)} IPs")
        
        for i, ip in enumerate(ip_list, 1):
            logger.info(f"Processing {i}/{len(ip_list)}: {ip}")
            result = self.process_ip(ip)
            results.append(result)
        
        logger.info(f"Batch processing complete. Processed {len(results)} IPs")
        return results
    
    def generate_report(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary report of decisions"""
        if not results:
            return {
                'total_ips_analyzed': 0,
                'blocked_ips': 0,
                'accepted_ips': 0,
                'average_risk_score': 0,
                'high_confidence_decisions': 0,
                'timestamp': datetime.now().isoformat(),
                'decisions': []
            }
        
        blocked = sum(1 for r in results if r['decision'] == 'BLOCK')
        accepted = sum(1 for r in results if r['decision'] == 'ACCEPT')
        avg_risk = sum(r['risk_score'] for r in results) / len(results)
        
        report = {
            'total_ips_analyzed': len(results),
            'blocked_ips': blocked,
            'accepted_ips': accepted,
            'average_risk_score': round(avg_risk, 2),
            'high_confidence_decisions': sum(1 for r in results if r['confidence'] == 'High'),
            'medium_confidence_decisions': sum(1 for r in results if r['confidence'] == 'Medium'),
            'low_confidence_decisions': sum(1 for r in results if r['confidence'] == 'Low'),
            'timestamp': datetime.now().isoformat(),
            'decisions': results
        }
        
        return report
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics from the dataset"""
        if self.data is None:
            return {}
        
        stats = {
            'total_records': len(self.data),
            'unique_ips': len(self.ip_context),
            'unique_countries': self.data['source Geo Country Name'].nunique(),
            'unique_threat_types': self.data['Name'].nunique(),
            'date_range': {
                'start': str(self.data['TimeStamp'].min()),
                'end': str(self.data['TimeStamp'].max())
            },
            'device_actions': self.data['Device Action'].value_counts().to_dict(),
            'category_outcomes': self.data['CategoryOutcome'].value_counts().to_dict()
        }
        
        return stats


def main():
    """Main execution function"""
    
    # Configuration
    EXCEL_FILE = "security_events_3000.xlsx"
    
    # Get API key from environment variable or hardcode (not recommended)
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', 'YOUR_GEMINI_API_HERE')
    
    if GEMINI_API_KEY == 'YOUR_GEMINI_API_KEY_HERE':
        print("=" * 70)
        print("ERROR: Please set your Gemini API key!")
        print("=" * 70)
        print("\nOption 1 - Environment Variable (Recommended):")
        print("  export GEMINI_API_KEY='your_key_here'")
        print("\nOption 2 - Edit this file:")
        print("  Replace 'YOUR_GEMINI_API_KEY_HERE' with your actual key")
        print("\nGet your API key from: https://aistudio.google.com/apikey")
        print("=" * 70)
        return
    
    print("=" * 70)
    print("MCP SERVER - Autonomous IP Security Decision System")
    print("=" * 70)
    print(f"Excel File: {EXCEL_FILE}")
    print(f"API Key: {GEMINI_API_KEY[:10]}...{GEMINI_API_KEY[-4:]}")
    print("=" * 70)
    
    # Initialize server
    try:
        server = MCPSecurityServer(EXCEL_FILE, GEMINI_API_KEY)
    except Exception as e:
        print(f"Error initializing server: {e}")
        return
    
    # Load data
    if not server.load_data():
        print("Failed to load data. Exiting.")
        return
    
    # Display dataset statistics
    stats = server.get_statistics()
    print(f"\nDataset Statistics:")
    print(f"  Total Records: {stats['total_records']}")
    print(f"  Unique IPs: {stats['unique_ips']}")
    print(f"  Unique Countries: {stats['unique_countries']}")
    print(f"  Unique Threat Types: {stats['unique_threat_types']}")
    print(f"  Date Range: {stats['date_range']['start']} to {stats['date_range']['end']}")
    
    # Get sample IPs to analyze
    sample_ips = list(server.ip_context.keys())[:10]
    
    print(f"\nAnalyzing {len(sample_ips)} sample IPs...")
    print("=" * 70)
    
    # Process IPs
    results = server.batch_process(sample_ips)
    
    # Generate report
    report = server.generate_report(results)
    
    # Display results
    print("\n" + "=" * 70)
    print("ANALYSIS REPORT")
    print("=" * 70)
    print(f"Total IPs Analyzed: {report['total_ips_analyzed']}")
    print(f"Blocked IPs: {report['blocked_ips']} ({report['blocked_ips']/report['total_ips_analyzed']*100:.1f}%)")
    print(f"Accepted IPs: {report['accepted_ips']} ({report['accepted_ips']/report['total_ips_analyzed']*100:.1f}%)")
    print(f"Average Risk Score: {report['average_risk_score']}/100")
    print(f"High Confidence Decisions: {report['high_confidence_decisions']} ({report['high_confidence_decisions']/report['total_ips_analyzed']*100:.1f}%)")
    print(f"Medium Confidence Decisions: {report['medium_confidence_decisions']} ({report['medium_confidence_decisions']/report['total_ips_analyzed']*100:.1f}%)")
    print(f"Low Confidence Decisions: {report['low_confidence_decisions']} ({report['low_confidence_decisions']/report['total_ips_analyzed']*100:.1f}%)")
    
    print("\n" + "-" * 70)
    print("INDIVIDUAL DECISIONS (Top 5):")
    print("-" * 70)
    
    for i, result in enumerate(results[:5], 1):
        print(f"\n{i}. IP Address: {result['ip_address']}")
        print(f"   Total Events: {result['context']['total_events']}")
        print(f"   Decision: {result['decision']} (Confidence: {result['confidence']})")
        print(f"   Risk Score: {result['risk_score']}/100")
        print(f"   Reasoning: {result['reasoning']}")
        print(f"   Recommendation: {result['recommendation']}")
    
    # Save full report to JSON
    output_file = 'mcp_analysis_report.json'
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print("\n" + "=" * 70)
        print(f"✓ Full report saved to: {output_file}")
        print("=" * 70)
    except Exception as e:
        print(f"\n✗ Error saving report: {e}")
    
    # Save summary to text file
    summary_file = 'mcp_summary.txt'
    try:
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("MCP-SIEM ANALYSIS SUMMARY\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Analysis Date: {report['timestamp']}\n")
            f.write(f"Total IPs Analyzed: {report['total_ips_analyzed']}\n")
            f.write(f"Blocked: {report['blocked_ips']} ({report['blocked_ips']/report['total_ips_analyzed']*100:.1f}%)\n")
            f.write(f"Accepted: {report['accepted_ips']} ({report['accepted_ips']/report['total_ips_analyzed']*100:.1f}%)\n")
            f.write(f"Average Risk Score: {report['average_risk_score']}/100\n")
            f.write(f"High Confidence: {report['high_confidence_decisions']}\n\n")
            
            f.write("-" * 70 + "\n")
            f.write("DETAILED RESULTS:\n")
            f.write("-" * 70 + "\n\n")
            
            for i, result in enumerate(results, 1):
                f.write(f"{i}. {result['ip_address']}\n")
                f.write(f"   Decision: {result['decision']} | Confidence: {result['confidence']} | Risk: {result['risk_score']}/100\n")
                f.write(f"   {result['reasoning']}\n\n")
        
        print(f"✓ Summary saved to: {summary_file}")
    except Exception as e:
        print(f"✗ Error saving summary: {e}")
    
    print("\n" + "=" * 70)
    print("Analysis Complete!")
    print("=" * 70)


if __name__ == "__main__":

    main()
