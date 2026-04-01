import os


def find_node_projects(paths):
    """Return list of directory paths containing package.json, excluding node_modules."""
    projects = []
    for root_path in paths:
        if not os.path.isdir(root_path):
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root_path):
                dirnames[:] = [d for d in dirnames if d != 'node_modules']
                if 'package.json' in filenames:
                    projects.append(dirpath)
        except Exception:
            pass
    return projects
