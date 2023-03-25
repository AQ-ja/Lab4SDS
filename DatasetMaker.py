import os
import pefile


folder_path = 'MALWR/'
data_malware = []


for filename in os.listdir(folder_path):
    if filename != '.DS_Store':  
        file_path = os.path.join(folder_path, filename)
        pe = pefile.PE(file_path)

        # Extrae la información del PE header
        pe_header = {}
        pe_header['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        pe_header['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment


        # Extrae información de las secciones
        sections = []
        for section in pe.sections:
            section_data = {}
            section_data['Name'] = section.Name.decode('utf-8').rstrip('\x00')
            section_data['VirtualAddress'] = hex(section.VirtualAddress)
            sections.append(section_data)

        # Extrae información de las llamadas
        imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            import_data = {}
            import_data['DLL'] = entry.dll.decode('utf-8').rstrip('\x00')
            import_data['Functions'] = []
            for function in entry.imports:
                import_data['Functions'].append(function.name.decode('utf-8'))
            imports.append(import_data)
	
        # Agrega la información del malware a la lista
        data_malware.append({
            'Filename': filename,
            'PEHeader': pe_header,
            'Sections': sections,
            'Imports': imports
        })

# Guarda los datos en un archivo CSV
import csv

with open('dataset.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Filename', 'PEHeader', 'Sections', 'Imports'])
    for malware in data_malware:
        writer.writerow([malware['Filename'], malware['PEHeader'], malware['Sections'], malware['Imports']])