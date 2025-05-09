import os
import re
import subprocess
import json
import csv
from datetime import datetime, timezone

AUTHFILE_PATH = 'Path to pull secret'

def reformat_quay_urls(input_txt):
    if not os.path.exists(input_txt):
        print("🚫 File not found. Please check the path and try again.")
        return None

    output_txt = "formatted_images.txt"
    pattern = re.compile(r"https://quay\.io/repository/([^/]+)/([^/]+)/manifest/(sha256:[a-f0-9]+)")

    formatted = []
    with open(input_txt, 'r') as infile:
        for line in infile:
            line = line.strip()
            match = pattern.search(line)
            if match:
                namespace, repo, sha = match.groups()
                formatted.append(f"quay.io/{namespace}/{repo}@{sha}")

    with open(output_txt, 'w') as outfile:
        for line in formatted:
            outfile.write(f"{line}\n")

    print(f"✅ Reformatted image list saved to: {output_txt}")
    return output_txt

def sanitize_image_name(image):
    if '@sha256@sha256:' in image:
        image = image.replace('@sha256@sha256:', '@sha256:')
    return image.strip()

def podman_pull_image(image):
    image = sanitize_image_name(image)
    cmd = ['podman', 'pull']

    if 'quay.io/openshift-release-dev' in image:
        cmd.extend(['--authfile', AUTHFILE_PATH])

    cmd.append(image)

    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to pull {image}:\n{e.stderr.strip()}")
        return False

def get_image_info(image):
    image = sanitize_image_name(image)

    if not podman_pull_image(image):
        return {
            "Image": image,
            "Build Date": "Pull Error",
            "Age (days)": "Error",
            "Version": "Error"
        }

    try:
        result = subprocess.run(
            ['podman', 'inspect', image],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )
        data = json.loads(result.stdout)[0]
        labels = data.get('Config', {}).get('Labels', {})
        build_date_str = labels.get('build-date')
        version = labels.get('version', 'N/A')

        if build_date_str:
            try:
                if 'Z' in build_date_str:
                    build_date = datetime.fromisoformat(build_date_str.replace('Z', '+00:00'))
                else:
                    build_date = datetime.fromisoformat(build_date_str).replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - build_date).days
            except ValueError:
                build_date = 'Invalid format'
                age_days = 'N/A'
        else:
            build_date = 'N/A'
            age_days = 'N/A'

        return {
            "Image": image,
            "Build Date": str(build_date),
            "Age (days)": age_days,
            "Version": version
        }

    except subprocess.CalledProcessError as e:
        print(f"❌ Error inspecting image {image}:\n{e.stderr.strip()}")
        return {
            "Image": image,
            "Build Date": "Inspect Error",
            "Age (days)": "Error",
            "Version": "Error"
        }

def main():
    input_txt = input("📂 Enter the path to your original .txt file with Quay URLs: ").strip()
    formatted_file = reformat_quay_urls(input_txt)
    if not formatted_file:
        return

    today_str = datetime.now().strftime("%d.%m.%Y")
    output_csv = f"image-age-{today_str}.csv"

    with open(formatted_file, 'r') as file:
        images = [sanitize_image_name(line) for line in file if line.strip()]

    results = [get_image_info(image) for image in images]

    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ["Image", "Build Date", "Age (days)", "Version"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\n✅ Done! Output saved to: {output_csv}")

if __name__ == "__main__":
    main()
