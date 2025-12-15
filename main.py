from core.pipeline import ThreatIntelPipeline

def main():
    print("🚀 Threat Intelligence Pipeline Started")
    pipeline = ThreatIntelPipeline()

    input_file = "input/sample_scan.json"
    result = pipeline.run(input_file)

    if result["status"] == "success":
        print("✅ Pipeline completed successfully")
        print("📄 Output saved to output/level2.json")
    else:
        print("❌ Pipeline failed")
        print(result)

if __name__ == "__main__":
    main()
