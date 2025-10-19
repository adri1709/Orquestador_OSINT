import networkx as nx
from collections import defaultdict
import re

def extract_entities(osint_data):
    """
    Extrae entidades de los resultados OSINT para correlación
    """
    entities = {
        "domains": set(),
        "ips": set(),
        "emails": set(),
        "phones": set(),
        "usernames": set(),
        "organizations": set(),
        "locations": set(),
        "nameservers": set()
    }
    
    relationships = []
    
    for result in osint_data.get("results", []):
        module = result.get("module")
        
        # WHOIS
        if module == "whois" and result.get("result"):
            res = result["result"]
            domain = res.get("domain_name")
            if domain:
                entities["domains"].add(domain)
                
                if res.get("registrar_abuse_email"):
                    email = res["registrar_abuse_email"]
                    entities["emails"].add(email)
                    relationships.append((domain, email, "registrar_email"))
                
                if res.get("org"):
                    org = res["org"]
                    entities["organizations"].add(org)
                    relationships.append((domain, org, "owned_by"))
                
                if res.get("name_servers"):
                    for ns in res["name_servers"][:3]:
                        entities["nameservers"].add(ns)
                        relationships.append((domain, ns, "uses_nameserver"))
        
        # DNS
        elif module == "dns" and result.get("records"):
            domain = result.get("input")
            if domain:
                entities["domains"].add(domain)
                
                # IPs from A records
                a_records = result["records"].get("A", [])
                if isinstance(a_records, list):
                    for ip in a_records:
                        entities["ips"].add(ip)
                        relationships.append((domain, ip, "resolves_to"))
                
                # Nameservers
                ns_records = result["records"].get("NS", [])
                if isinstance(ns_records, list):
                    for ns in ns_records:
                        entities["nameservers"].add(ns)
                        relationships.append((domain, ns, "nameserver"))
        
        # Shodan
        elif module == "shodan_host" and result.get("result"):
            res = result["result"]
            ip = res.get("ip")
            if ip:
                entities["ips"].add(ip)
                
                if res.get("organization"):
                    org = res["organization"]
                    entities["organizations"].add(org)
                    relationships.append((ip, org, "belongs_to"))
                
                if res.get("hostnames"):
                    for hostname in res["hostnames"][:3]:
                        entities["domains"].add(hostname)
                        relationships.append((ip, hostname, "hostname"))
                
                if res.get("city") and res.get("country"):
                    location = f"{res['city']}, {res['country']}"
                    entities["locations"].add(location)
                    relationships.append((ip, location, "located_in"))
        
        # Username
        elif module == "username_check" and result.get("sites"):
            username = result.get("input")
            if username:
                entities["usernames"].add(username)
                
                for site in result["sites"]:
                    if site.get("exists"):
                        url = site["url"]
                        domain = re.search(r'https?://(?:www\.)?([^/]+)', url)
                        if domain:
                            platform = domain.group(1)
                            relationships.append((username, platform, "account_on"))
        
        # Phone
        elif module == "phone_lookup" and result.get("result"):
            res = result["result"]
            phone = res.get("number")
            if phone:
                entities["phones"].add(phone)
                
                if res.get("location"):
                    location = res["location"]
                    entities["locations"].add(location)
                    relationships.append((phone, location, "registered_in"))
        
        # EXIF
        elif module == "exif_metadata" and result.get("results"):
            for img in result["results"]:
                if img.get("metadata", {}).get("gps"):
                    gps = img["metadata"]["gps"]
                    if gps.get("Latitude_Decimal") and gps.get("Longitude_Decimal"):
                        location = f"{gps['Latitude_Decimal']:.4f}, {gps['Longitude_Decimal']:.4f}"
                        entities["locations"].add(location)
    
    return entities, relationships


def build_relationship_graph(osint_data):
    """
    Construye un grafo NetworkX con las relaciones encontradas
    """
    entities, relationships = extract_entities(osint_data)
    
    G = nx.DiGraph()
    
    # Añadir nodos con tipos
    for entity_type, entity_set in entities.items():
        for entity in entity_set:
            G.add_node(entity, type=entity_type, label=str(entity)[:30])
    
    # Añadir aristas
    for source, target, rel_type in relationships:
        G.add_edge(source, target, relationship=rel_type)
    
    return G, entities, relationships


def generate_graphviz_visualization(osint_data, output_path):
    """
    Genera visualización con matplotlib + networkx (sin dependencias binarias)
    """
    import matplotlib
    matplotlib.use('Agg')  # Backend sin GUI
    import matplotlib.pyplot as plt
    
    G, entities, relationships = build_relationship_graph(osint_data)
    
    if G.number_of_nodes() == 0:
        return {"error": "No hay suficientes datos para generar un grafo"}
    
    # Configurar figura
    plt.figure(figsize=(16, 10))
    
    # Colores por tipo de entidad
    color_map = {
        "domains": "#90EE90",
        "ips": "#FFB6C1",
        "emails": "#ADD8E6",
        "phones": "#FFD700",
        "usernames": "#DDA0DD",
        "organizations": "#FFA07A",
        "locations": "#98FB98",
        "nameservers": "#F0E68C"
    }
    
    # Asignar colores a nodos
    node_colors = []
    for node in G.nodes():
        node_type = G.nodes[node].get('type', 'unknown')
        node_colors.append(color_map.get(node_type, '#CCCCCC'))
    
    # Layout del grafo
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
    
    # Dibujar nodos
    nx.draw_networkx_nodes(G, pos, 
                           node_color=node_colors,
                           node_size=3000,
                           alpha=0.9,
                           edgecolors='black',
                           linewidths=2)
    
    # Dibujar aristas
    nx.draw_networkx_edges(G, pos,
                           edge_color='gray',
                           arrows=True,
                           arrowsize=20,
                           arrowstyle='->',
                           width=2,
                           alpha=0.6)
    
    # Etiquetas de nodos
    labels = {}
    for node in G.nodes():
        label = str(node)
        if len(label) > 20:
            label = label[:17] + "..."
        labels[node] = label
    
    nx.draw_networkx_labels(G, pos, labels,
                            font_size=9,
                            font_weight='bold',
                            font_family='sans-serif')
    
    # Etiquetas de aristas (relaciones)
    edge_labels = nx.get_edge_attributes(G, 'relationship')
    nx.draw_networkx_edge_labels(G, pos, edge_labels,
                                 font_size=7,
                                 font_color='darkblue')
    
    # Título y leyenda
    plt.title("OSINT Correlation Graph", fontsize=20, fontweight='bold', pad=20)
    
    # Crear leyenda
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=color_map['domains'], label='Dominios'),
        Patch(facecolor=color_map['ips'], label='IPs'),
        Patch(facecolor=color_map['emails'], label='Emails'),
        Patch(facecolor=color_map['phones'], label='Teléfonos'),
        Patch(facecolor=color_map['usernames'], label='Usuarios'),
        Patch(facecolor=color_map['organizations'], label='Organizaciones'),
        Patch(facecolor=color_map['locations'], label='Ubicaciones'),
        Patch(facecolor=color_map['nameservers'], label='Nameservers')
    ]
    plt.legend(handles=legend_elements, loc='upper left', fontsize=10)
    
    plt.axis('off')
    plt.tight_layout()
    
    # Guardar imagen
    output_file = f"{output_path}.png"
    plt.savefig(output_file, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    
    return {
        "graph_file": output_file,
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "entities": {k: len(v) for k, v in entities.items() if v}
    }


def export_to_maltego(osint_data, output_path):
    """
    Exporta a formato CSV compatible con Maltego
    """
    import csv
    
    entities, relationships = extract_entities(osint_data)
    
    # Archivo de entidades
    entities_file = f"{output_path}_entities.csv"
    with open(entities_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Entity', 'Type'])
        
        for entity_type, entity_set in entities.items():
            for entity in entity_set:
                writer.writerow([entity, entity_type])
    
    # Archivo de relaciones
    relations_file = f"{output_path}_relations.csv"
    with open(relations_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Source', 'Target', 'Relationship'])
        
        for source, target, rel_type in relationships:
            writer.writerow([source, target, rel_type])
    
    return {
        "entities_file": entities_file,
        "relations_file": relations_file,
        "total_entities": sum(len(v) for v in entities.values()),
        "total_relations": len(relationships)
    }


def generate_correlation_report(osint_data):
    """
    Genera informe de correlaciones encontradas
    """
    entities, relationships = extract_entities(osint_data)
    
    report = {
        "summary": {
            "total_entities": sum(len(v) for v in entities.values()),
            "total_relationships": len(relationships),
            "entity_breakdown": {k: len(v) for k, v in entities.items() if v}
        },
        "entities": {k: list(v) for k, v in entities.items() if v},
        "relationships": [
            {"source": s, "target": t, "type": r} 
            for s, t, r in relationships
        ]
    }
    
    # Detectar correlaciones interesantes
    correlations = []
    
    # Mismo dominio en múltiples contextos
    domain_count = defaultdict(int)
    for s, t, r in relationships:
        if s in entities["domains"]:
            domain_count[s] += 1
    
    for domain, count in domain_count.items():
        if count > 2:
            correlations.append({
                "type": "high_connectivity",
                "entity": domain,
                "connections": count,
                "note": "Dominio con múltiples conexiones"
            })
    
    report["correlations"] = correlations
    
    return report