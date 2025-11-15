def run(input_path, output_path=None):
    events = load_json_lines(input_path)
    # do analysis
    findings = [...]
    print_findings(findings, title="...")

    if output_path:
        with open(output_path, "w") as f:
            ...
