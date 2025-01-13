import csv
from collections import defaultdict



def parse_lookup_table(lookup_file):
    lookup = defaultdict(list)
    with open(lookup_file, 'r') as file:
        reader = csv.DictReader(file)
        # Ensure headers are stripped of quotes and spaces
        reader.fieldnames = [field.strip().strip('"') for field in reader.fieldnames]
        if 'dstport' not in reader.fieldnames or 'protocol' not in reader.fieldnames or 'tag' not in reader.fieldnames:
            raise KeyError("CSV file is missing one or more required headers: 'dstport', 'protocol', 'tag'")
        for row in reader:
            port = row['dstport'].strip().strip('"')
            protocol = row['protocol'].strip().lower().strip('"')
            tag = row['tag'].strip().strip('"')
            lookup[(port, protocol)].append(tag)
    return lookup


def load_protocols(protocol_file):
    """
    Load protocol mappings from a CSV file into a dictionary.
    :param protocol_file: Path to the protocol CSV file.
    :return: Dictionary with protocol numbers as keys and protocol names as values.
    """
    protocols = {}
    with open(protocol_file, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            protocol_number = row['number'].strip()
            protocol_name = row['name'].strip().lower()
            protocols[protocol_number] = protocol_name
    return protocols


def parse_flow_logs(flow_log_file, protocols):
    """
    Parse flow logs and map protocol numbers to protocol names using a provided dictionary.
    :param flow_log_file: Path to the flow log file.
    :param protocols: Dictionary with protocol mappings.
    :return: List of (destination port, protocol) tuples.
    """
    logs = []
    with open(flow_log_file, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) >= 11:
                dst_port = parts[6].strip()
                protocol_number = parts[7].strip()

                # Map protocol number to protocol name using the protocols dictionary
                protocol = protocols.get(protocol_number, 'unknown')

                # Only add the destination port for matching
                logs.append((dst_port, protocol.lower()))
    return logs


def map_tags_and_generate_output(logs, lookup):
    tag_counts = defaultdict(int)
    port_protocol_counts = defaultdict(int)
    untagged_count = 0

    for dst_port, protocol in logs:
        key = (dst_port, protocol)
        tags = lookup.get(key, [])

        if tags:
            for tag in tags:
                tag_counts[tag.lower()] += 1
        else:
            untagged_count += 1

        # Only count the standard service ports, not ephemeral ports
        port_protocol_counts[key] += 1

    # Sort outputs
    tag_output = sorted([(tag, count) for tag, count in tag_counts.items()])

    port_protocol_output = sorted(
        [(port, protocol, count) for (port, protocol), count in port_protocol_counts.items()] # Sort by port (numerically), then protocol
    )

    return tag_output, port_protocol_output, untagged_count





def write_output(tag_output, port_protocol_output, untagged_count, output_file):
    with open(output_file, 'w') as file:
        file.write("Tag Counts:\n")
        file.write("Tag,Count\n")
        for tag, count in tag_output:
            file.write(f"{tag},{count}\n")
        file.write(f"Untagged,{untagged_count}\n\n")

        file.write("Port/Protocol Combination Counts:\n")
        file.write("Port,Protocol,Count\n")
        for port, protocol, count in port_protocol_output:
            file.write(f"{port},{protocol},{count}\n")

def main():
    lookup_file = "lookup_tables.csv"
    flow_log_file = "flow_logs.txt"
    output_file = "output.csv"
    protocol_file="protocols.csv"

    protocols = load_protocols(protocol_file)
    # Parse input files
    lookup = parse_lookup_table(lookup_file)
    logs = parse_flow_logs(flow_log_file,protocols)

    # Map tags and generate outputs
    tag_output, port_protocol_output, untagged_count = map_tags_and_generate_output(logs, lookup)

    # Write outputs to a file
    write_output(tag_output, port_protocol_output, untagged_count, output_file)
    print(f"Output written to {output_file}")

if __name__ == "__main__":
    main()
