import yaml
import sys
import os # Módulo para operaciones del sistema, como manejar archivos y directorios

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
    # (Esta función no ha cambiado)
    if not isinstance(jackett_field, dict) or 'selector' not in jackett_field:
        return ""
    selector = jackett_field['selector']
    attribute = jackett_field.get('attribute')
    if attribute:
        return f"{selector}@{attribute}"
    return selector

def convert_jackett_to_scarf(jackett_data):
    # (Esta función no ha cambiado)
    scarf_def = {
        'key': jackett_data.get('id', 'unknown'), 'name': jackett_data.get('name', 'Unknown'),
        'description': jackett_data.get('description', ''), 'language': jackett_data.get('language', 'en-US'),
        'schedule': '@every 1h'
    }
    search_info = jackett_data.get('search', {})
    scarf_search = {
        'type': 'html', 'urls': jackett_data.get('links', []), 'params': {},
        'results': {'rows_selector': search_info.get('rows', {}).get('selector', ''), 'fields': {}}
    }
    jackett_fields = search_info.get('fields', {})
    scarf_fields = {
        'title': {'selector': convert_field_selector(jackett_fields.get('title'))},
        'details_url': {'selector': convert_field_selector(jackett_fields.get('details'))},
        'download_url': {'selector': convert_field_selector(jackett_fields.get('download'))},
        'size': {'selector': convert_field_selector(jackett_fields.get('size'))},
        'seeders': {'selector': convert_field_selector(jackett_fields.get('seeders'))},
        'leechers': {'selector': convert_field_selector(jackett_fields.get('leechers'))},
        'publish_date': {'selector': convert_field_selector(jackett_fields.get('date'))}
    }
    scarf_search['results']['fields'] = scarf_fields
    if not scarf_fields['download_url']['selector']:
        download_info = jackett_data.get('download', {})
        if download_info.get('selectors'):
            selector_info = download_info['selectors'][0]
            scarf_search['results']['download_selector'] = convert_field_selector(selector_info)
    scarf_def['search'] = scarf_search
    scarf_cat_mappings = []
    jackett_cat_mappings = jackett_data.get('caps', {}).get('categorymappings', [])
    for mapping in jackett_cat_mappings:
        jackett_cat_str = mapping.get('cat')
        torznab_cat_id = JACKETT_CAT_TO_TORZNAB.get(jackett_cat_str)
        if torznab_cat_id:
            scarf_cat_mappings.append({'indexer_cat': str(mapping.get('id')), 'torznab_cat': torznab_cat_id})
        else:
            print(f"  [!] Advertencia: No se encontró mapeo para la categoría de Jackett: '{jackett_cat_str}'")
    scarf_def['category_mappings'] = scarf_cat_mappings
    return scarf_def

def process_file(input_file, output_file):
    """Procesa un único archivo de definición."""
    print(f"\n[*] Procesando archivo: {os.path.basename(input_file)}")
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            jackett_data = yaml.safe_load(f)
        
        scarf_data = convert_jackett_to_scarf(jackett_data)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(scarf_data, f, sort_keys=False, indent=2)
            
        print(f"  [+] Convertido y guardado en: {os.path.basename(output_file)}")
    except Exception as e:
        print(f"  [!] Error al procesar {os.path.basename(input_file)}: {e}")

def main():
    """Punto de entrada del script. Ahora maneja archivos y directorios."""
    if len(sys.argv) != 3:
        print("Uso:")
        print("  - Para un solo archivo: python convert.py <entrada.yml> <salida.yml>")
        print("  - Para un directorio:   python convert.py <directorio_entrada> <directorio_salida>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    # --- Lógica para manejar directorios ---
    if os.path.isdir(input_path):
        print(f"[*] Detectado modo directorio. Procesando desde '{input_path}' hacia '{output_path}'.")
        # Crear el directorio de salida si no existe
        if not os.path.exists(output_path):
            print(f"[*] Creando directorio de salida: {output_path}")
            os.makedirs(output_path)
        
        converted_count = 0
        # Recorrer todos los archivos del directorio de entrada
        for filename in os.listdir(input_path):
            if filename.endswith(('.yml', '.yaml')):
                input_file = os.path.join(input_path, filename)
                output_file = os.path.join(output_path, filename)
                process_file(input_file, output_file)
                converted_count += 1
        
        print(f"\n[+] Proceso completado. Se convirtieron {converted_count} archivos.")

    # --- Lógica para manejar un solo archivo ---
    elif os.path.isfile(input_path):
        print("[*] Detectado modo de archivo único.")
        process_file(input_path, output_path)

    else:
        print(f"[!] Error: La ruta de entrada '{input_path}' no es un archivo ni un directorio válido.")
        sys.exit(1)

if __name__ == '__main__':
    main()