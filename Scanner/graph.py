import matplotlib.pyplot as plt

def generate_graph(open_ports, safe_ports):
    labels = ['Vulnerable', 'Safe']
    values = [open_ports, safe_ports]

    plt.figure()
    plt.bar(labels, values)
    plt.title("Security Status")

    plt.savefig("static/graph.png")
    plt.close()