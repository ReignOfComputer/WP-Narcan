import os
import argparse
import requests
import zipfile
import shutil
import tempfile
import time

def is_valid_wp_directory(directory):
    # Check for wp-config.php file
    wp_config_exists = os.path.isfile(os.path.join(directory, 'wp-config.php'))
    
    # Check for wp-content/ directory
    wp_content_exists = os.path.isdir(os.path.join(directory, 'wp-content'))
    
    # Check for wp-content/themes/ directory
    themes_exists = os.path.isdir(os.path.join(directory, 'wp-content', 'themes'))
    
    # Check for wp-content/plugins/ directory
    plugins_exists = os.path.isdir(os.path.join(directory, 'wp-content', 'plugins'))
    
    # Return True if all required elements exist
    return wp_config_exists and wp_content_exists and themes_exists and plugins_exists

def download_and_extract(url, extract_to, is_wp=False):
    with requests.get(url, stream=True) as response:
        if response.status_code != 200:
            raise Exception(f"Not found in WordPress repository")
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            for chunk in response.iter_content(chunk_size=128):
                tmp_file.write(chunk)
    try:
        with zipfile.ZipFile(tmp_file.name, 'r') as zip_ref:
            if is_wp:  # Special handling for WordPress itself
                zip_ref.extractall(extract_to)
                wp_dir = os.path.join(extract_to, 'wordpress')
                for filename in os.listdir(wp_dir):
                    shutil.move(os.path.join(wp_dir, filename), extract_to)
                os.rmdir(wp_dir)
            else:
                zip_ref.extractall(extract_to)
    except zipfile.BadZipFile:
        raise Exception("File is not a zip file")
    finally:
        os.remove(tmp_file.name)

def prompt_for_confirmation(items, content_type):
    print(f"Found {len(items)} {content_type}(s):")
    for item in items:
        print(f"- {item}")
    user_response = input(f"Do you want to proceed with downloading and installing these {content_type}(s)? (y/n): ").strip().lower()
    return user_response == 'y'

def handle_wp_content(content_type, source_dir, dest_dir):
    source_path = os.path.join(source_dir, 'wp-content', content_type + 's')
    dest_path = os.path.join(dest_dir, 'wp-content', content_type + 's')
    os.makedirs(dest_path, exist_ok=True)

    items = [item for item in os.listdir(source_path) if os.path.isdir(os.path.join(source_path, item))]
    if prompt_for_confirmation(items, content_type):
        missing_items = []
        for item in items:
            download_url = f'https://downloads.wordpress.org/{content_type}/{item}.zip'
            try:
                download_and_extract(download_url, dest_path)
                print(f"Successfully downloaded {content_type}: {item}")
            except Exception as e:
                print(f"Error downloading {content_type} '{item}': {e}")
                missing_items.append(item)
        if missing_items:
            with open(os.path.join(dest_path, 'missing.txt'), 'w') as f:
                f.write("\n".join(missing_items))
            print(f"Missing {content_type}(s) listed in {os.path.join(dest_path, 'missing.txt')}")
    else:
        print(f"Skipping {content_type} download and installation.")

def is_silence_is_golden_file(file_path):
    """Check if a file is a 'Silence is golden' file or is empty."""
    silence_is_golden_content = "<?php\n// Silence is golden.\n"
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            return content == silence_is_golden_content or content == ""
    except IOError:
        # In case of an error opening/reading the file, assume it's not safe
        return False
        
def scan_and_clean_uploads(uploads_dir):
    print(f"Scanning 'uploads' directory: {uploads_dir}")  # Log the uploads_dir path
    suspicious_extensions = ['.php', '.php3', '.php4', '.php5', '.php7', '.phtml', '.htaccess']  # Include .htaccess
    for root, dirs, files in os.walk(uploads_dir):
        for file in files:
            file_path = os.path.join(root, file)
            # Check for specified PHP related extensions and .htaccess files
            if any(file.endswith(ext) for ext in suspicious_extensions):
                # Only delete files that are neither 'Silence is golden' nor empty
                if not is_silence_is_golden_file(file_path):
                    os.remove(file_path)
                    print(f"Deleted file: {file_path}")

def main():
    parser = argparse.ArgumentParser(description="Rebuild a WordPress installation.")
    parser.add_argument('directory', type=str, help='Path to the WordPress directory')
    args = parser.parse_args()
    
    print("Welcome to WP Narcan")
    print("Author: ReignOfComputer")
    print();

    if not is_valid_wp_directory(args.directory):
        print("Invalid WordPress directory")
        return
    
    print("Found valid WordPress Installation.")
    
    # Assuming args.directory is the path to the original directory
    original_dir_path = os.path.abspath(args.directory)  # Ensure we have an absolute path
    parent_dir = os.path.dirname(original_dir_path)  # Get the parent directory of the original directory
    directory_name = os.path.basename(original_dir_path)  # Get the name of the original directory
    new_dir_name = f"{directory_name}-rebuilt"  # Create the new directory name by appending '-rebuilt'
    new_dir = os.path.join(parent_dir, new_dir_name)  # Combine the parent directory with the new directory name
    os.makedirs(new_dir, exist_ok=True)
    
    print("Created rebuilt directory.")

    # Download and extract WordPress
    download_and_extract('https://wordpress.org/latest.zip', new_dir, is_wp=True)
    
    print("Downloaded WordPress Core.")
    print()

    # Handle plugins and themes
    for content in ['plugin', 'theme']:
        handle_wp_content(content, args.directory, new_dir)
        print()

    # Check and copy uploads directory if it exists
    uploads_dir = os.path.join(args.directory, 'wp-content', 'uploads')
    rebuilt_uploads_dir = os.path.join(new_dir, 'wp-content', 'uploads')
    if os.path.exists(uploads_dir):
        shutil.copytree(uploads_dir, rebuilt_uploads_dir, dirs_exist_ok=True)
        # After copying, scan and clean the uploads directory
        scan_and_clean_uploads(rebuilt_uploads_dir)
        print(f"Scanned and cleaned 'uploads' directory in {rebuilt_uploads_dir}.")
    else:
        print(f"'uploads' directory does not exist in {args.directory}, skipping this step.")
        
    print()
    
    # Copy wp-config.php to the new directory
    wp_config_src = os.path.join(original_dir_path, 'wp-config.php')
    wp_config_dest = os.path.join(new_dir, 'wp-config.php')
    if os.path.exists(wp_config_src):
        shutil.copy(wp_config_src, wp_config_dest)
        print("Successfully copied 'wp-config.php' to the rebuilt directory. Manually review this file for anomalies.")
    else:
        print("Error: 'wp-config.php' does not exist in the original directory.")
    
    print()
    print("All done, take note of any missing items and manually verify the files before replacing server copy.")

if __name__ == "__main__":
    main()
