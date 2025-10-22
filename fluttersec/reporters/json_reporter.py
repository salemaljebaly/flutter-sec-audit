"""
JSON report generator
"""
import json
from pathlib import Path
from typing import Optional, Dict
from ..models import AnalysisResult


class JSONReporter:
    """Generate JSON reports for CI/CD integration"""

    def generate(self, result: AnalysisResult, output_path: str, attack_result: Optional[Dict] = None) -> None:
        """Generate JSON report"""
        report_data = result.to_dict()

        # Add attack simulation data if available
        if attack_result:
            report_data['attack_simulation'] = {
                'most_likely_attacker': attack_result['most_likely_attacker'],
                'time_to_compromise_minutes': attack_result['overall_time_to_compromise'],
                'attack_scenario': attack_result['attack_scenario'],
                'profiles': {
                    level: {
                        'can_exploit': data['can_exploit'],
                        'time_minutes': data['time_minutes'],
                        'exploitable_findings': data['exploitable_findings']
                    }
                    for level, data in attack_result['profiles'].items()
                }
            }

        # Write to file
        output_file = Path(output_path)
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
