import yaml
import sys
import os
import re

# --- Mapeo de Categorías de Jackett a Torznab ---
JACKETT_CAT_TO_TORZNAB = {
    "Console": 1000,
    "Movies": 2000,
    "Movies/Foreign": 2010,
    "Movies/Other": 2020,
    "Movies/SD": 2030,
    "Movies/HD": 2040,
    "Movies/UHD": 2050,
    "Movies/3D": 2060,
    "Movies/BluRay": 2070,
    "Movies/DVD": 2080,
    "Audio": 3000,
    "Audio/MP3": 3010,
    "Audio/Video": 3020,
    "Audio/Audiobook": 3030,
    "Audio/Lossless": 3040,
    "PC": 4000,
    "PC/0day": 4010,
    "PC/ISO": 4020,
    "PC/Mac": 4030,
    "PC/Mobile-Other": 4040,
    "PC/Games": 4050,
    "PC/Mobile-iOS": 4060,
    "PC/Mobile-Android": 4070,
    "TV": 5000,
    "TV/WEB-DL": 5010,
    "TV/Foreign": 5020,
    "TV/SD": 5030,
    "TV/HD": 5040,
    "TV/UHD": 5050,
    "TV/Other": 5060,
    "TV/Sport": 5070,
    "TV/Anime": 5080,
    "XXX": 6000,
    "XXX/DVD": 6010,
    "XXX/WMV": 6020,
    "XXX/XviD": 6030,
    "XXX/x264": 6040,
    "XXX/Pack": 6050,
    "XXX/ImgSet": 6060,
    "XXX/Other": 6070,
    "Books": 7000,
    "Books/Mags": 7010,
    "Books/Ebook": 7020,
    "Books/Comics": 7030,
    "Other": 8000,
    # Alias comunes en Jackett
    "TV/Documentary": 5070,
}

def convert_field_selector(jackett_field):
    if not isinstance(jackett_field, dict) or 'selector' not in jackett_field:
        return ""
    selector = jackett_field['selector']
    attribute = jackett_field.get('attribute')

    # Basic filter conversion for common cases
    filters = jackett_field.get('filters', [])
    for f in filters:
        if f.get('name') == 'regexp' and 'src=' in f.get('args', ''):
             # Extract URL from onmouseover attribute
            match = re.search(r"src=\\'(.*?)\\'", selector)
            if match:
                return match.group(1)
        if f.get('name') == 'querystring':
            return f"{selector}@{f.get('args')}"


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
        'enabled': True, # Let's enable by default
        'language': jackett_data.get('language', 'en-US'),
        'schedule': '@hourly'
    }

    # Handle private/semi-private trackers
    if scarf_def['type'] in ['private', 'semiprivate']:
        scarf_def['username'] = ""
        scarf_def['password'] = ""

        # Convert user-configurable settings
        user_config = {}
        for setting in jackett_data.get('settings', []):
            if setting['type'] in ['select', 'checkbox', 'text', 'password']:
                 # Use the default value specified in the Jackett file
                user_config[setting['name']] = str(setting.get('default', ''))
        if user_config:
            scarf_def['user_config'] = user_config


        # Convert login block
        login_info = jackett_data.get('login', {})
        if login_info.get('path'):
            scarf_def['login'] = {
                'url': f"{jackett_data.get('links', [''])[0]}{login_info['path']}",
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
            'rows_selector': search_info.get('rows', {}).get('selector', ''),
            'fields': {}
        }
    }
    
    # Construct search URLs and params from Jackett's 'paths' and 'inputs'
    base_url = jackett_data.get('links', [''])[0]
    search_path_info = search_info.get('paths', [{}])[0]
    search_path = search_path_info.get('path', '')
    
    # Simplified template conversion
    search_url = f"{base_url}{search_path}"
    
    # Convert search inputs to URL params or body
    search_inputs = search_info.get('inputs', {})
    final_params = {}
    for key, value in search_inputs.items():
        if isinstance(value, str):
            # A simplified replacement for Jackett's complex templating
            if 'Keywords' in value or 'Query.IMDBID' in value:
                final_params[key] = '{{.Query}}'
            elif 'Categories' in value:
                 final_params[key] = '{{.Category}}'
            elif '.Config' in value:
                config_key = value.split('.')[-1].strip(' }')
                final_params[key] = f'{{{{.Config.{config_key}}}}}' # Keep as template
            # Ignore static or complex inputs for now
            elif '{{' not in value:
                 final_params[key] = value

    # Add the constructed URL and params
    scarf_search['urls'].append(search_url)
    scarf_search['params'] = final_params


    # --- Field Selectors ---
    jackett_fields = search_info.get('fields', {})
    scarf_fields = {
        'title': {'selector': convert_field_selector(jackett_fields.get('title'))},
        'details_url': {'selector': convert_field_selector(jackett_fields.get('details'))},
        'download_url': {'selector': convert_field_selector(jackett_fields.get('download'))},
        'size': {'selector': convert_field_selector(jackett_fields.get('size'))},
        'seeders': {'selector': convert_field_selector(jackett_fields.get('seeders'))},
        'leechers': {'selector': convert_field_selector(jackett_fields.get('leechers'))},
        # Combine date fields if they exist
        'publish_date': {'selector': convert_field_selector(jackett_fields.get('date') or jackett_fields.get('date_year') or jackett_fields.get('date_day'))}
    }
    scarf_search['results']['fields'] = scarf_fields

    # Handle multi-step download fetching
    if not scarf_fields['download_url']['selector']:
        download_info = jackett_data.get('download', {})
        if download_info.get('selectors'):
            selector_info = download_info['selectors'][0]
            scarf_search['results']['download_selector'] = convert_field_selector(selector_info)

    scarf_def['search'] = scarf_search

    # --- Category Mappings ---
    scarf_cat_mappings = []
    jackett_cat_mappings = jackett_data.get('caps', {}).get('categorymappings', [])
    for mapping in jackett_cat_mappings:
        jackett_cat_str = mapping.get('cat')
        torznab_cat_id = JACKETT_CAT_TO_TORZNAB.get(jackett_cat_str)
        if torznab_cat_id:
            scarf_cat_mappings.append({'indexer_cat': str(mapping.get('id')), 'torznab_cat': torznab_cat_id})
        else:
            print(f"  [!] Warning: No mapping found for Jackett category: '{jackett_cat_str}'")

    scarf_def['category_mappings'] = scarf_cat_mappings

    return scarf_def


def process_file(input_file, output_file):
    """Procesa un único archivo de definición."""
    print(f"\n[*] Processing file: {os.path.basename(input_file)}")
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            # Use a loader that preserves comments if needed in the future
            jackett_data = yaml.safe_load(f)
        
        scarf_data = convert_jackett_to_scarf(jackett_data)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # Dump the converted data into the Scarf YAML format
            yaml.dump(scarf_data, f, sort_keys=False, indent=2, default_flow_style=False)
            
        print(f"  [+] Converted and saved to: {os.path.basename(output_file)}")
    except Exception as e:
        print(f"  [!] Error processing {os.path.basename(input_file)}: {e}")

def main():
    """Punto de entrada del script. Ahora maneja archivos y directorios."""
    if len(sys.argv) != 3:
        print("Usage:")
        print("  - For a single file: python convert.py <input.yml> <output.yml>")
        print("  - For a directory:   python convert.py <input_directory> <output_directory>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    # --- Lógica para manejar directorios ---
    if os.path.isdir(input_path):
        print(f"[*] Directory mode detected. Processing from '{input_path}' to '{output_path}'.")
        # Crear el directorio de salida si no existe
        if not os.path.exists(output_path):
            print(f"[*] Creating output directory: {output_path}")
            os.makedirs(output_path)
        
        converted_count = 0
        # Recorrer todos los archivos del directorio de entrada
        for filename in os.listdir(input_path):
            if filename.endswith(('.yml', '.yaml')):
                input_file = os.path.join(input_path, filename)
                output_file = os.path.join(output_path, filename)
                process_file(input_file, output_file)
                converted_count += 1
        
        print(f"\n[+] Process completed. Converted {converted_count} files.")

    # --- Lógica para manejar un solo archivo ---
    elif os.path.isfile(input_path):
        print("[*] Single file mode detected.")
        process_file(input_path, output_path)

    else:
        print(f"[!] Error: Input path '{input_path}' is not a valid file or directory.")
        sys.exit(1)

if __name__ == '__main__':
    main()