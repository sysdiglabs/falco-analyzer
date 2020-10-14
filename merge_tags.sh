#!/bin/bash
# merge_tags
python3 falco_analyzer.py merge_tags ../falco/rules.falco_versions/0.22.1/falco_rules.yaml ../../draios_falco_rules/rules_tags/falco_rules.yaml falco_rules_merged.yaml
python3 falco_analyzer.py merge_tags ../falco/rules.falco_versions/0.22.1/k8s_audit_rules.yaml ../../draios_falco_rules/rules_tags/k8s_audit_rules.yaml k8s_audit_rules_merged.yaml