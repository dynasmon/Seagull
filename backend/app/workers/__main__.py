from app.workers.rules_engine import run_all_rules


def main():
    alerts = run_all_rules()
    print(f"Created {len(alerts)} alerts")


if __name__ == "__main__":
    main()
