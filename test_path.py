import os

# Check current directory
current_dir = os.path.dirname(os.path.abspath(__file__))
print("Main Folder:", current_dir)

# Check models folder
models_dir = os.path.join(current_dir, 'models')
print("Models Folder exists?:", os.path.exists(models_dir))

# Check exact file name inside models folder
if os.path.exists(models_dir):
    print("Files inside models folder:", os.listdir(models_dir))