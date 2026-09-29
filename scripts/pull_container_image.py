import requests
import json
import tarfile
import os
import sys

def pull_image(image_name, tag='latest', out_file='image.tar'):
    print(f"Pulling {image_name}:{tag}...")
    
    # Get token
    auth_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/{image_name}:pull"
    r = requests.get(auth_url)
    token = r.json().get('token')
    
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.docker.distribution.manifest.v2+json'}
    
    # Get manifest
    registry_url = f"https://registry-1.docker.io/v2/library/{image_name}/manifests/{tag}"
    r = requests.get(registry_url, headers=headers)
    manifest = r.json()
    
    if 'layers' not in manifest:
        print("Error getting layers:", manifest)
        sys.exit(1)
        
    layers = manifest['layers']
    print(f"Found {len(layers)} layers.")
    
    if not os.path.exists("data"):
        os.makedirs("data")
        
    out_path = os.path.join("data", out_file)
    with tarfile.open(out_path, "w") as tar:
        for i, layer in enumerate(layers):
            digest = layer['digest']
            print(f"Downloading layer {i+1}/{len(layers)}: {digest}...")
            layer_url = f"https://registry-1.docker.io/v2/library/{image_name}/blobs/{digest}"
            lr = requests.get(layer_url, headers={'Authorization': f'Bearer {token}'}, stream=True)
            
            layer_filename = f"data/layer_{i}.tar.gz"
            with open(layer_filename, "wb") as f:
                for chunk in lr.iter_content(chunk_size=8192):
                    f.write(chunk)
                    
            tar.add(layer_filename, arcname=f"{digest}.tar.gz")
            os.remove(layer_filename)
            
    print(f"Saved to {out_path}")

if __name__ == "__main__":
    pull_image("alpine", "latest", "alpine_latest.tar")
    pull_image("nginx", "alpine", "nginx_alpine.tar")
