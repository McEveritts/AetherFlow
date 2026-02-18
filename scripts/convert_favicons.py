from PIL import Image
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
source_path = os.path.join(script_dir, '../dashboard/img/logo-aetherflow-new.png')
base_dir = os.path.join(script_dir, '../dashboard/img/favicon')

if not os.path.exists(base_dir):
    os.makedirs(base_dir)

try:
    img = Image.open(source_path)
    
    # Favicon 32x32
    img.resize((32, 32), Image.Resampling.LANCZOS).save(os.path.join(base_dir, 'favicon-32x32.png'))
    print("Generated favicon-32x32.png")
    
    # Favicon 16x16
    img.resize((16, 16), Image.Resampling.LANCZOS).save(os.path.join(base_dir, 'favicon-16x16.png'))
    print("Generated favicon-16x16.png")
    
    # Apple Touch Icon 180x180
    img.resize((180, 180), Image.Resampling.LANCZOS).save(os.path.join(base_dir, 'apple-touch-icon.png'))
    print("Generated apple-touch-icon.png")
    
    # Favicon.ico (Multi-size)
    img.save(os.path.join(base_dir, '../favicon.ico'), format='ICO', sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])
    print("Generated favicon.ico")
    
    # Android Chrome 192x192
    img.resize((192, 192), Image.Resampling.LANCZOS).save(os.path.join(base_dir, 'android-chrome-192x192.png'))
    
    # Android Chrome 512x512
    img.resize((512, 512), Image.Resampling.LANCZOS).save(os.path.join(base_dir, 'android-chrome-512x512.png'))

    print("All favicons generated successfully.")

except Exception as e:
    print(f"Error: {e}")
