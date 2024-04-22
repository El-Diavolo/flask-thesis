import os
import shutil

def delete_files_in_directories(directory):
    # Iterate over all the items in the given directory
    for item in os.listdir(directory):
        item_path = os.path.join(directory, item)
        # Check if the current item is a directory
        if os.path.isdir(item_path):
            # Iterate over all files in the directory
            for filename in os.listdir(item_path):
                file_path = os.path.join(item_path, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)  # Remove the file or link
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)  # Remove the directory and all its contents
                except Exception as e:
                    print(f'Failed to delete {file_path}. Reason: {e}')
        elif os.path.isfile(item_path):
            #to delete files directly in the 'results' directory, uncomment the next line
            # os.unlink(item_path)
            pass

# Usage
directory = 'results'
delete_files_in_directories(directory)
