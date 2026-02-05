#!/usr/bin/env python3
import argparse
from PIL import Image
import sys

def rgba_to_hex(rgba):
    r, g, b, a = rgba
    return f"#{r:02x}{g:02x}{b:02x}", a / 255.0

def trace_contours_for_color(width, height, pixels, target_color):
    """
    Finds all contour loops for a specific color in the pixel grid.
    Returns a list of polygons (each polygon is a list of (x,y) tuples).
    """
    # 1. Build a set of edges. 
    # An edge is defined by ((x1, y1), (x2, y2)) directed so that the color is on the RIGHT?
    # Let's use standard marching: valid pixel is "inside".
    # We look for boundaries between "inside" (target color) and "outside" (other color).
    
    # Edges: vertical or horizontal segments of length 1.
    # Represented as (start_x, start_y, end_x, end_y)
    edges = set()
    
    for y in range(height):
        for x in range(width):
            if pixels[x, y] != target_color:
                continue
                
            # Check 4 neighbors
            # Top (x, y-1)
            if y == 0 or pixels[x, y-1] != target_color:
                # Top edge of this pixel: (x, y) -> (x+1, y)
                edges.add((x, y, x+1, y))
                
            # Bottom (x, y+1)
            if y == height - 1 or pixels[x, y+1] != target_color:
                # Bottom edge: (x+1, y+1) -> (x, y+1) (Right to Left to maintain CW/CCW winding?)
                # Let's stick to consistent CW winding for "islands" and CCW for "holes" automatically handled if we follow "color on right" rule.
                # If we walk along the edge with the pixel on our RIGHT:
                # Top: x,y -> x+1,y
                # Right: x+1,y -> x+1,y+1
                # Bottom: x+1,y+1 -> x,y+1
                # Left: x,y+1 -> x,y
                edges.add((x+1, y+1, x, y+1))

            # Left (x-1, y)
            if x == 0 or pixels[x-1, y] != target_color:
                # Left edge: (x, y+1) -> (x, y)
                edges.add((x, y+1, x, y))
                
            # Right (x+1, y)
            if x == width - 1 or pixels[x+1, y] != target_color:
                # Right edge: (x+1, y) -> (x+1, y+1)
                edges.add((x+1, y, x+1, y+1))

    # 2. Connect edges into loops
    # Optimize: Build adjacency map for O(1) lookup
    # key: start_vertex (x,y), value: list of end_vertices? 
    # Since it's a manifold, each vertex should have 1 outgoing edge if we follow consistent winding?
    # Actually, a vertex can have 2 outgoing edges if two corners meet? 
    # But disjoint sets. Let's map start -> set(ends)
    
    edge_map = {}
    for e in edges:
        start = (e[0], e[1])
        end = (e[2], e[3])
        if start not in edge_map: edge_map[start] = []
        edge_map[start].append(end)
        
    polygons = []
    
    # Process edges until empty
    visited_edges = set() # Check against this instead of modifying edges set directly if tricky
    # But simpler: Consume edge_map
    
    start_nodes = list(edge_map.keys())
    
    while edge_map:
        # Pick a random start point
        start_pt = next(iter(edge_map))
        
        # Start a loop
        current_poly = [start_pt]
        
        # Consume the edge
        next_pt = edge_map[start_pt].pop()
        if not edge_map[start_pt]: del edge_map[start_pt]
        
        while next_pt != current_poly[0]:
            current_poly.append(next_pt)
            
            if next_pt not in edge_map:
                # Should not happen in closed loops
                break
                
            # Pick next edge
            new_next = edge_map[next_pt].pop()
            if not edge_map[next_pt]: del edge_map[next_pt]
            
            next_pt = new_next
            
        # Loop closed or broken
        # 3. Simplify collinear points
        if len(current_poly) > 2:
            simplified = []
            if not current_poly: continue
            
            # We need to look at triplets (prev, curr, next)
            # Since it's a loop, handle wrap around
            
            # Easier approach: build list of vectors, merge if same direction
            vectors = []
            for i in range(len(current_poly)):
                p1 = current_poly[i]
                p2 = current_poly[(i+1) % len(current_poly)]
                vectors.append( (p2[0]-p1[0], p2[1]-p1[1], p1) ) # dx, dy, start_pt
            
            merged_vectors = []
            if not vectors: continue
            
            current_dx, current_dy, current_start = vectors[0]
            current_count = 1
            
            for i in range(1, len(vectors)):
                dx, dy, pt = vectors[i]
                if (dx != 0 and dx * current_dx > 0 and dy == 0 and current_dy == 0) or \
                   (dy != 0 and dy * current_dy > 0 and dx == 0 and current_dx == 0):
                   # Same direction (horizontal or vertical)
                   # Extend current vector
                    current_dx += dx
                    current_dy += dy
                else:
                    # Direction change, push old vector
                    merged_vectors.append((current_start, (current_start[0]+current_dx, current_start[1]+current_dy)))
                    current_dx, current_dy, current_start = dx, dy, pt
            
            # Push last
            merged_vectors.append((current_start, (current_start[0]+current_dx, current_start[1]+current_dy)))

            # Check if first and last can merge (loop wrap)
            if len(merged_vectors) > 1:
                first = merged_vectors[0]
                last = merged_vectors[-1]
                # Check logic... simpler: just rebuild polygon from segments
                
            final_poly = [v[0] for v in merged_vectors]
            polygons.append(final_poly)

    return polygons

def optimize_to_paths(input_path, output_path, max_colors=32, target_size=512):
    try:
        img = Image.open(input_path).convert("RGBA")
    except Exception as e:
        print(f"Error: {e}")
        return

    # Resize/Quantize same as before
    if img.size[0] != target_size:
        img = img.resize((target_size, target_size), Image.Resampling.NEAREST)
    
    print(f"Quantizing to {max_colors} colors...")
    img = img.quantize(colors=max_colors, method=2).convert("RGBA")
    width, height = img.size
    pixels = img.load()
    
    # Identify unique colors
    unique_colors = set()
    for y in range(height):
        for x in range(width):
            unique_colors.add(pixels[x, y])
            
    print(f"Found {len(unique_colors)} unique colors. Tracing contours...")
    
    with open(output_path, "w") as f:
        f.write(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" shape-rendering="crispEdges">')
        
        for color in unique_colors:
            if color[3] < 10: continue # Skip transparent
            
            polygons = trace_contours_for_color(width, height, pixels, color)
            
            if not polygons: continue
            
            path_data = ""
            for poly in polygons:
                if not poly: continue
                # M x y
                path_data += f"M{poly[0][0]} {poly[0][1]}"
                # L x y ...
                for i in range(1, len(poly)):
                    path_data += f" L{poly[i][0]} {poly[i][1]}"
                path_data += "Z "
            
            hex_col, alpha = rgba_to_hex(color)
            opacity = f' fill-opacity="{alpha:.2g}"' if alpha < 0.99 else ''
            
            f.write(f'<path fill="{hex_col}"{opacity} d="{path_data}"/>')

        f.write('</svg>')
    
    import os
    size = os.path.getsize(output_path) / 1024
    print(f"Done! {output_path} is {size:.2f} KB")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('input')
    parser.add_argument('output')
    parser.add_argument('--colors', type=int, default=32)
    parser.add_argument('--size', type=int, default=512)
    args = parser.parse_args()
    optimize_to_paths(args.input, args.output, args.colors, args.size)
