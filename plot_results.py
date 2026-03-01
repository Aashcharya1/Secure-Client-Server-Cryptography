import pandas as pd
import matplotlib.pyplot as plt

# 1. Load the data
try:
    data = pd.read_csv('performance_results.csv')
except FileNotFoundError:
    print("Error: 'performance_results.csv' not found. Run your C++ benchmark first.")
    exit()

# 2. Calculate averages for annotations
aes_avg = data['AES_Time_ms'].mean()
rsa_avg = data['RSA_Time_ms'].mean()
max_run = data['Run'].max()

# 3. Set up a modern, professional figure style
plt.figure(figsize=(12, 6.5), facecolor='#f8f9fa')
ax = plt.gca()
ax.set_facecolor('#ffffff')

# 4. Plot RSA (Red) with shading
plt.plot(data['Run'], data['RSA_Time_ms'], label='RSA-3072 OAEP (Asymmetric)', color='#e63946', linewidth=2.5)
plt.fill_between(data['Run'], data['RSA_Time_ms'], color='#e63946', alpha=0.08)

# 5. Plot AES (Blue) with shading
plt.plot(data['Run'], data['AES_Time_ms'], label='AES-128-CBC (Symmetric)', color='#1d3557', linewidth=2.5)
plt.fill_between(data['Run'], data['AES_Time_ms'], color='#1d3557', alpha=0.08)

# 6. Add Average Trendlines
plt.axhline(rsa_avg, color='#e63946', linestyle='--', linewidth=1.5, alpha=0.6)
plt.axhline(aes_avg, color='#1d3557', linestyle='--', linewidth=1.5, alpha=0.6)

# Add text boxes for the exact average times
plt.text(max_run + 1, rsa_avg, f'Avg: {rsa_avg:.1f} ms', color='#e63946', va='center', fontweight='bold', fontsize=10)
plt.text(max_run + 1, aes_avg, f'Avg: {aes_avg:.1f} ms', color='#1d3557', va='center', fontweight='bold', fontsize=10)

# 7. Clean up grid and borders (Tufte style)
plt.grid(color='#e5e5e5', linestyle='-', linewidth=1, alpha=0.7)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_color('#cccccc')
ax.spines['bottom'].set_color('#cccccc')

# 8. Titles and Labels
plt.title('Cryptographic Performance Overhead: AES vs RSA', fontsize=16, fontweight='bold', color='#111111', pad=20)
plt.xlabel('Execution Run (1KB Payload)', fontsize=12, fontweight='bold', color='#333333')
plt.ylabel('Total Latency (Milliseconds)', fontsize=12, fontweight='bold', color='#333333')

# 9. Format Legend
plt.legend(loc='center right', frameon=True, shadow=True, fancybox=True, borderpad=1, fontsize=11)

# 10. Save and render
plt.tight_layout()
plt.margins(x=0.01) # Reduce white space on the sides
plt.savefig('performance_comparison.png', dpi=300, bbox_inches='tight')
print("Professional plot saved as 'performance_comparison.png'")
plt.show()