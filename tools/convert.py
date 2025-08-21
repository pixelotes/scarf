import yaml
import sys
import os
import re

# --- Jackett to Torznab Category Mapping ---
JACKETT_CAT_TO_TORZNAB = {
    "Console": 1000,
    "Movies": 2000, "Movies/Foreign": 2010, "Movies/Other": 2020, "Movies/SD": 2030,
    "Movies/HD": 2040, "Movies/UHD": 2050, "Movies/3D": 2060, "Movies/BluRay": 2070,
    "Movies/DVD": 2080, "Audio": 3000, "Audio/MP3": 3010, "Audio/Video": 3020,
    "Audio/Audiobook": 3030, "Audio/Lossless": 3040, "PC": 4000, "PC/0day": 4010,
    "PC/ISO": 4020, "PC/Mac": 4030, "PC/Mobile-Other": 4040, "PC/Games": 4050,
    "PC/Mobile-iOS": 4060, "PC/Mobile-Android": 4070, "TV": 5000, "TV/WEB-DL": 5010,
    "TV/Foreign": 5020, "TV/SD": 5030, "TV/HD": 5040, "TV/UHD": 5050,
    "TV/Other": 5060, "TV/Sport": 5070, "TV/Anime": 5080, "XXX": 6000,
    "XXX/DVD": 6010, "XXX/WMV": 6020, "XXX/XviD": 6030, "XXX/x264": 6040,
    "XXX/Pack": 6050, "XXX/ImgSet": 6060, "XXX/Other": 6070, "Books": 7000,
    "Books/Mags": 7010, "Books/Ebook": 7020, "Books/Comics": 7030, "Other": 8000,
    "TV/Documentary": 5070,
}

def convert_field_selector(jackett_field):
    if not isinstance(jackett_field, dict) or 'selector' not in jackett_field:
        return ""
    selector = jackett_field['selector']
    attribute = jackett_field.get('attribute')
    if attribute:
        return f"{selector}@{attribute}"
    return selector

def convert_jackett_to_scarf(jackett_data):
    # Basic info
    scarf_def = {
        'key': jackett_data.get('id', 'unknown'),
        'name': jackett_data.get('name', 'Unknown'),
        'description': jackett_data.get('description', ''),
        'type': jackett_data.get('type', 'public'),
        'enabled': True,
        'language': jackett_data.get('language', 'en-US'),
        'schedule': '@hourly'
    }

    # --- Dynamic Settings Block ---
    scarf_settings = []
    use_flaresolverr_default = 'false'
    
    for setting in jackett_data.get('settings', []):
        if setting.get('type') == 'info_flaresolverr':
            use_flaresolverr_default = 'true'
            continue # Skip adding the info field directly

        setting_type = setting.get('type')
        if setting_type in ['text', 'password', 'checkbox', 'select']:
            new_setting = {
                'name': setting.get('name'),
                'type': setting_type,
                'label': setting.get('label'),
                'default': str(setting.get('default', ''))
            }
            if setting_type == 'select':
                new_setting['options'] = setting.get('options', {})
            scarf_settings.append(new_setting)

    # Add the use_flaresolverr checkbox to all trackers
    scarf_settings.append({
        'name': 'use_flaresolverr',
        'type': 'checkbox',
        'label': 'Use FlareSolverr',
        'default': use_flaresolverr_default
    })

    if scarf_settings:
        scarf_def['settings'] = scarf_settings


    # Convert login block only for private/semiprivate trackers
    if scarf_def['type'] in ['private', 'semiprivate']:
        login_info = jackett_data.get('login', {})
        if login_info.get('path'):
            scarf_def['login'] = {
                'url': f"{jackett_data.get('links', [''])[0].rstrip('/')}/{login_info['path'].lstrip('/')}",
                'method': login_info.get('method', 'post'),
                'body': {k: v for k, v in login_info.get('inputs', {}).items() if v},
                'success_check': {
                    'contains': login_info.get('test', {}).get('selector', '')
                }
            }

    # --- Search Configuration ---
    search_info = jackett_data.get('search', {})
    scarf_search = {
        'type': 'html',
        'urls': [],
        'params': {},
        'results': {
            'rows_selector': re.sub(r'\{\{.*?\}\}', '', search_info.get('rows', {}).get('selector', '')).strip(),
            'fields': {}
        }
    }
    
    # --- NEW: Convert Headers ---
    jackett_headers = search_info.get('headers')
    if jackett_headers:
        scarf_headers = {}
        for key, value in jackett_headers.items():
            header_value = ''
            if isinstance(value, list) and len(value) > 0:
                header_value = value[0]
            elif isinstance(value, str):
                header_value = value
            
            # Convert Jackett's template syntax to Scarf's Go template syntax
            header_value = header_value.replace(' .Keywords ', '.Query').replace(' .Config.', '.Config.')
            scarf_headers[key] = header_value
        scarf_search['headers'] = scarf_headers


    base_url = jackett_data.get('links', [''])[0].rstrip('/')
    search_path_info = search_info.get('paths', [{}])[0]
    search_path = search_path_info.get('path', '').lstrip('/')
    
    # Build URL with query parameters from Jackett's 'inputs'
    url_template = f"{base_url}/{search_path}"
    params = {}
    for key, value in search_info.get('inputs', {}).items():
        if isinstance(value, str):
            # Convert Jackett's template syntax to Scarf's Go template syntax
            value = value.replace(' .Keywords ', '.Query').replace(' .Config.', '.Config.')
            # A simplified replacement for complex Jackett logic
            if '{{' in value:
                params[key] = value
            elif key != 'page': # Exclude static 'page' key from params
                params[key] = value

    # Construct the final URL template for Scarf
    param_strings = []
    for key, value in params.items():
        # Handle templated values
        if '{{' in value:
            # Clean up the template for Go
            go_template = re.sub(r'\{\{\s*if\s+\.Query\.Artist\s*\}\}(.*?)\{\{ else \}\}(.*?)\{\{ end \}\}','{{.Query}}', value)
            go_template = re.sub(r'\{\{\s*if\s+\.Query\.IMDBID\s*\}\}.*?\{\{ else \}\}(.*?)\{\{ end \}\}', r'{{.Query}}', go_template)
            go_template = go_template.replace('{{ range .Categories }}{{.}};{{end}}', '{{.Category}}')
            param_strings.append(f"{key}={go_template}")
        else:
            param_strings.append(f"{key}={value}")

    if param_strings:
        url_template += "?" + "&".join(param_strings)
        
    scarf_search['urls'].append(url_template)

    # --- Field Selectors ---
    jackett_fields = search_info.get('fields', {})
    scarf_fields = {
        'title': {'selector': convert_field_selector(jackett_fields.get('title'))},
        'details_url': {'selector': convert_field_selector(jackett_fields.get('details'))},
        'download_url': {'selector': convert_field_selector(jackett_fields.get('download'))},
        'size': {'selector': convert_field_selector(jackett_fields.get('size'))},
        'seeders': {'selector': convert_field_selector(jackett_fields.get('seeders'))},
        'leechers': {'selector': convert_field_selector(jackett_fields.get('leechers'))},
        'publish_date': {'selector': convert_field_selector(jackett_fields.get('date') or jackett_fields.get('date_day') or jackett_fields.get('date_year'))}
    }
    scarf_search['results']['fields'] = {k: v for k, v in scarf_fields.items() if v.get('selector')}

    scarf_def['search'] = scarf_search

    # --- Category Mappings ---
    scarf_cat_mappings = []
    for mapping in jackett_data.get('caps', {}).get('categorymappings', []):
        jackett_cat_str = mapping.get('cat')
        torznab_cat_id = JACKETT_CAT_TO_TORZNAB.get(jackett_cat_str)
        if torznab_cat_id:
            scarf_cat_mappings.append({'indexer_cat': str(mapping.get('id')), 'torznab_cat': torznab_cat_id})
        else:
            print(f"  [!] Warning: No mapping found for Jackett category: '{jackett_cat_str}'")

    if scarf_cat_mappings:
        scarf_def['category_mappings'] = scarf_cat_mappings

    return scarf_def

def process_file(input_file, output_file):
    """Processes a single definition file."""
    print(f"\n[*] Processing file: {os.path.basename(input_file)}")
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            # Workaround for files with BOM
            content = f.read()
            if content.startswith('\ufeff'):
                content = content[1:]
            jackett_data = yaml.safe_load(content)
        
        scarf_data = convert_jackett_to_scarf(jackett_data)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(scarf_data, f, sort_keys=False, indent=2, default_flow_style=False)
            
        print(f"  [+] Converted and saved to: {os.path.basename(output_file)}")
    except Exception as e:
        print(f"  [!] Error processing {os.path.basename(input_file)}: {e}")

def main():
    """Script entry point. Handles files and directories."""
    if len(sys.argv) != 3:
        print("Usage:")
        print("  - For a single file: python convert.py <input.yml> <output.yml>")
        print("  - For a directory:   python convert.py <input_directory> <output_directory>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    if os.path.isdir(input_path):
        print(f"[*] Directory mode detected. Processing from '{input_path}' to '{output_path}'.")
        if not os.path.exists(output_path):
            print(f"[*] Creating output directory: {output_path}")
            os.makedirs(output_path)
        
        converted_count = 0
        for filename in os.listdir(input_path):
            if filename.endswith(('.yml', '.yaml')):
                input_file = os.path.join(input_path, filename)
                output_file = os.path.join(output_path, filename)
                process_file(input_file, output_file)
                converted_count += 1
        
        print(f"\n[+] Process completed. Converted {converted_count} files.")

    elif os.path.isfile(input_path):
        print("[*] Single file mode detected.")
        process_file(input_path, output_path)

    else:
        print(f"[!] Error: Input path '{input_path}' is not a valid file or directory.")
        sys.exit(1)

if __name__ == '__main__':
    main()