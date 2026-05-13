"""
Banner and ASCII art for the CLI interface
"""

from colorama import Fore, Style

def display_banner():
    """Display the CyberWolf ASCII art banner"""
    
    banner = f"""{Fore.CYAN}
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗    ██╗ ██████╗ ██╗     ███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║    ██║██╔═══██╗██║     ██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║ █╗ ██║██║   ██║██║     █████╗  
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║███╗██║██║   ██║██║     ██╔══╝  
╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚███╔███╔╝╚██████╔╝███████╗██║     
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚═════╝ ╚══════╝╚═╝     
{Style.RESET_ALL}                                                                       
{Fore.WHITE}         ========= Automated Vulnerability Scanner =========          {Style.RESET_ALL}
{Fore.YELLOW}                   The Developed By CyberWolf Team                    {Style.RESET_ALL}
{Fore.WHITE}         =================================================          {Style.RESET_ALL}
"""
    
    wolf_art = f"""{Fore.CYAN}
                    ,     ,
                    |\\---/|
                   /       \\
                  |         |
                   \\       /
                    ||   ||
                    ||   ||
                    \'---\'
{Style.RESET_ALL}
"""

    print(banner)
    print(wolf_art)
