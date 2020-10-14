#!/bin/bash
# merge_tags
python3 falco_analyzer.py get_csv_tags falco_rules_merged.yaml falco_rules.csv
python3 falco_analyzer.py get_csv_tags k8s_audit_rules_merged.yaml k8s_audit_rules.csv