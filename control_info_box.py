#!/usr/bin/env python3
"""
Control Script for Attack Simulation Info Box
This script helps you control the display of the attack simulation information box.
"""

import os
import sys

def update_config(setting, value):
    """Update the config.py file with new settings."""
    config_file = "config.py"
    
    if not os.path.exists(config_file):
        print(f"❌ Config file {config_file} not found!")
        return False
    
    try:
        with open(config_file, 'r') as f:
            content = f.read()
        
        # Update the specific setting
        if setting == "SHOW_ATTACK_SIMULATION_INFO":
            if value.lower() in ['true', '1', 'yes', 'on']:
                new_content = content.replace(
                    "SHOW_ATTACK_SIMULATION_INFO = False",
                    "SHOW_ATTACK_SIMULATION_INFO = True"
                ).replace(
                    "SHOW_ATTACK_SIMULATION_INFO = True",
                    "SHOW_ATTACK_SIMULATION_INFO = True"
                )
            else:
                new_content = content.replace(
                    "SHOW_ATTACK_SIMULATION_INFO = True",
                    "SHOW_ATTACK_SIMULATION_INFO = False"
                ).replace(
                    "SHOW_ATTACK_SIMULATION_INFO = False",
                    "SHOW_ATTACK_SIMULATION_INFO = False"
                )
        
        elif setting == "INFO_BOX_STYLE":
            # Remove existing style setting
            import re
            new_content = re.sub(
                r'INFO_BOX_STYLE = "[^"]*"',
                f'INFO_BOX_STYLE = "{value}"',
                content
            )
        
        # Write back to file
        with open(config_file, 'w') as f:
            f.write(new_content)
        
        print(f"✅ Successfully updated {setting} to {value}")
        return True
        
    except Exception as e:
        print(f"❌ Error updating config: {e}")
        return False

def show_current_settings():
    """Show current configuration settings."""
    try:
        from config import SHOW_ATTACK_SIMULATION_INFO, INFO_BOX_STYLE
        print("\n📋 Current Settings:")
        print(f"   Show Attack Simulation Info: {SHOW_ATTACK_SIMULATION_INFO}")
        print(f"   Info Box Style: {INFO_BOX_STYLE}")
    except ImportError:
        print("❌ Could not import config settings")

def main():
    """Main function to control the info box."""
    print("🔧 Attack Simulation Info Box Controller")
    print("=" * 50)
    
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python control_info_box.py show    - Show current settings")
        print("  python control_info_box.py hide    - Hide the info box completely")
        print("  python control_info_box.py show    - Show the info box always visible")
        print("  python control_info_box.py expand  - Show as collapsible expander")
        print("  python control_info_box.py style <style> - Set specific style")
        print("\nAvailable styles:")
        print("  - hidden: Don't show the info box")
        print("  - always_visible: Always show the info box")
        print("  - collapsible: Show as expandable section")
        
        show_current_settings()
        return
    
    command = sys.argv[1].lower()
    
    if command == "show":
        show_current_settings()
        print("\nTo change settings, use:")
        print("  python control_info_box.py style always_visible")
        
    elif command == "hide":
        update_config("SHOW_ATTACK_SIMULATION_INFO", "False")
        update_config("INFO_BOX_STYLE", "hidden")
        print("\n✅ Info box is now hidden")
        
    elif command == "expand":
        update_config("SHOW_ATTACK_SIMULATION_INFO", "True")
        update_config("INFO_BOX_STYLE", "collapsible")
        print("\n✅ Info box is now collapsible")
        
    elif command == "style":
        if len(sys.argv) < 3:
            print("❌ Please specify a style: hidden, always_visible, or collapsible")
            return
        
        style = sys.argv[2].lower()
        if style not in ["hidden", "always_visible", "collapsible"]:
            print("❌ Invalid style. Use: hidden, always_visible, or collapsible")
            return
        
        if style == "hidden":
            update_config("SHOW_ATTACK_SIMULATION_INFO", "False")
        else:
            update_config("SHOW_ATTACK_SIMULATION_INFO", "True")
        
        update_config("INFO_BOX_STYLE", style)
        print(f"\n✅ Info box style set to: {style}")
        
    else:
        print(f"❌ Unknown command: {command}")
        print("Use: show, hide, expand, or style")

if __name__ == "__main__":
    main()
