#!/usr/bin/env python3
import argparse
from PIL import Image
import sys
import os

def rgba_to_hex(rgba):
    r, g, b, a = rgba
    return f"#{r:02x}{g:02x}{b:02x}", a / 255.0

def optimize_image_and_generate_svg(input_path, output_path, max_colors=32, target_size=512):
    # Load image
    try:
        img = Image.open(input_path).convert("RGBA")
    except Exception as e:
        print(f"Error opening image: {e}")
        sys.exit(1)
        
    original_size = img.size
    print(f"Original size: {original_size}")

    # 1. Resize if needed
    if original_size[0] != target_size or original_size[1] != target_size:
        print(f"Resizing to {target_size}x{target_size} for optimization...")
        img = img.resize((target_size, target_size), Image.Resampling.NEAREST)
    
    # 2. Quantize colors
    # Use Fast Octree (method=2) which supports RGBA
    print(f"Quantizing to {max_colors} colors to reduce file size...")
    img_quantized = img.quantize(colors=max_colors, method=2).convert("RGBA")
    
    width, height = img_quantized.size
    pixels = img_quantized.load()

    print("Generating SVG...")
    with open(output_path, "w") as f:
        f.write(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" shape-rendering="crispEdges">')
        
        rect_count = 0
        for y in range(height):
            current_color = None
            start_x = 0
            
            for x in range(width):
                pixel = pixels[x, y]
                
                if pixel != current_color:
                    if current_color is not None:
                        # Draw previous run
                        _, prev_alpha = rgba_to_hex(current_color)
                        # Skip transparent or nearly transparent
                        if prev_alpha > 0.05: 
                            prev_hex, _ = rgba_to_hex(current_color)
                            width_rect = x - start_x
                            
                            # Optimization: Don't write opacity if 1.0 (default)
                            # Round opacity to 2 decimals to save bytes
                            if prev_alpha > 0.99:
                                opacity_attr = ''
                            else:
                                opacity_attr = f' fill-opacity="{prev_alpha:.2g}"' # .2g removes trailing zeros
                                
                            f.write(f'<rect x="{start_x}" y="{y}" width="{width_rect}" height="1" fill="{prev_hex}"{opacity_attr}/>')
                            rect_count += 1
                    
                    current_color = pixel
                    start_x = x
            
            # Final run
            if current_color is not None:
                _, prev_alpha = rgba_to_hex(current_color)
                if prev_alpha > 0.05:
                    prev_hex, _ = rgba_to_hex(current_color)
                    width_rect = width - start_x
                    if prev_alpha > 0.99:
                        opacity_attr = ''
                    else:
                        opacity_attr = f' fill-opacity="{prev_alpha:.2g}"'
                        
                    f.write(f'<rect x="{start_x}" y="{y}" width="{width_rect}" height="1" fill="{prev_hex}"{opacity_attr}/>')
                    rect_count += 1

        f.write('</svg>')
    
    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"Done! Saved to {output_path}")
    print(f"Total rectangles: {rect_count}")
    print(f"File size: {file_size_mb:.2f} MB")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert PNG to optimized Pixel Art SVG')
    parser.add_argument('input', help='Input PNG file')
    parser.add_argument('output', help='Output SVG file')
    parser.add_argument('--size', type=int, default=512, help='Target resolution (default: 512)')
    parser.add_argument('--colors', type=int, default=32, help='Max colors for quantization (default: 32)')
    
    args = parser.parse_args()
    
    optimize_image_and_generate_svg(args.input, args.output, args.colors, args.size)
