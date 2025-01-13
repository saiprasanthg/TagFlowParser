import csv
from collections import defaultdict



def parse_lookup_table(lookup_file):
    """
    Parses a CSV file containing a lookup table of (dstport, protocol) to tags and returns it as a dictionary.

    :param lookup_file: Path to the lookup table CSV file.
    :return: A defaultdict where keys are tuples (dstport, protocol) and values are lists of tags.
    """
    # Initialize a defaultdict to store the lookup data
    lookup = defaultdict(list)

    # Open the CSV file for reading
    with open(lookup_file, 'r') as file:
        reader = csv.DictReader(file)

        # Ensure headers are cleaned of quotes and spaces for consistency
        reader.fieldnames = [field.strip().strip('"') for field in reader.fieldnames]

        # Validate that the required headers are present in the file
        if 'dstport' not in reader.fieldnames or 'protocol' not in reader.fieldnames or 'tag' not in reader.fieldnames:
            raise KeyError("CSV file is missing one or more required headers: 'dstport', 'protocol', 'tag'")

        # Iterate through each row in the CSV file
        for row in reader:
            # Clean and extract the destination port, protocol, and tag fields
            port = row['dstport'].strip().strip('"')  # Remove extra spaces and quotes
            protocol = row['protocol'].strip().lower().strip('"')  # Convert protocol to lowercase for case-insensitive matching
            tag = row['tag'].strip().strip('"')  # Remove extra spaces and quotes from the tag

            # Add the tag to the list associated with the (port, protocol) key in the lookup dictionary
            lookup[(port, protocol)].append(tag)

    # Return the populated lookup table
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
    """
    Maps flow log entries to tags using the lookup table and generates tag counts,
    port/protocol counts, and the number of untagged entries.

    :param logs: List of (dst_port, protocol) tuples from flow logs.
    :param lookup: Lookup table mapping (dst_port, protocol) to tags.
    :return: Tuple containing sorted tag counts, port/protocol counts, and untagged count.
    """
    # Initialize counters for tags, port/protocol combinations, and untagged entries
    tag_counts = defaultdict(int)
    port_protocol_counts = defaultdict(int)
    untagged_count = 0

    # Process each log entry
    for dst_port, protocol in logs:
        key = (dst_port, protocol)
        tags = lookup.get(key, [])  # Get tags for the port/protocol combination

        if tags:
            # Increment counts for each tag
            for tag in tags:
                tag_counts[tag.lower()] += 1
        else:
            # Increment untagged count if no tags match
            untagged_count += 1

        # Increment counts for the port/protocol combination
        port_protocol_counts[key] += 1

    # Sort tag counts alphabetically by tag name
    tag_output = sorted([(tag, count) for tag, count in tag_counts.items()])

    # Sort port/protocol counts by port (numerically) and then by protocol
    port_protocol_output = sorted(
        [(port, protocol, count) for (port, protocol), count in port_protocol_counts.items()]
    )

    # Return the sorted outputs and the untagged count
    return tag_output, port_protocol_output, untagged_count






def write_output(tag_output, port_protocol_output, untagged_count, output_file):
    """
    Writes the tag counts, port/protocol combination counts, and untagged count to an output file.

    :param tag_output: List of (tag, count) tuples sorted alphabetically by tag.
    :param port_protocol_output: List of (port, protocol, count) tuples sorted by port and protocol.
    :param untagged_count: Count of untagged entries.
    :param output_file: Path to the file where the output will be written.
    """
    # Open the output file in write mode
    with open(output_file, 'w') as file:
        # Write tag counts
        file.write("Tag Counts:\n")
        file.write("Tag,Count\n")
        for tag, count in tag_output:
            file.write(f"{tag},{count}\n")
        # Write untagged count as a special entry
        file.write(f"Untagged,{untagged_count}\n\n")

        # Write port/protocol combination counts
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
