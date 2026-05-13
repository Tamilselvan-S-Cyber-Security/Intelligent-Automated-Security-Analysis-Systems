"""
Cybersecurity Tips Collection for the Cyber Wolf Security Analyzer
This module provides a collection of cybersecurity tips with different difficulty levels.
"""

# Collection of cybersecurity tips
SECURITY_TIPS = [
    # Beginner Tips
    {
        "level": "beginner",
        "title": "Use Strong, Unique Passwords",
        "content": "Create passwords with at least 12 characters combining uppercase, lowercase, numbers, and symbols. Use a different password for each account and consider a password manager.",
        "icon": "🔑"
    },
    {
        "level": "beginner",
        "title": "Enable Two-Factor Authentication",
        "content": "Add an extra layer of security to your accounts by enabling 2FA whenever possible. This provides protection even if your password is compromised.",
        "icon": "🔐"
    },
    {
        "level": "beginner",
        "title": "Keep Software Updated",
        "content": "Always install updates for your operating system, applications, and devices. Updates often contain security patches for known vulnerabilities.",
        "icon": "🔄"
    },
    {
        "level": "beginner",
        "title": "Be Wary of Phishing Attempts",
        "content": "Don't click on suspicious links or download attachments from unknown senders. Verify the sender's email address and check for grammar or spelling errors.",
        "icon": "🎣"
    },
    {
        "level": "beginner",
        "title": "Secure Your Home Network",
        "content": "Change default router passwords, use WPA3 encryption when available, and consider setting up a guest network for visitors to your home.",
        "icon": "🏠"
    },
    
    # Intermediate Tips
    {
        "level": "intermediate",
        "title": "Use a VPN for Public Wi-Fi",
        "content": "When connecting to public Wi-Fi networks, always use a reputable VPN service to encrypt your traffic and protect your data from eavesdropping.",
        "icon": "🌐"
    },
    {
        "level": "intermediate",
        "title": "Implement Email Filtering",
        "content": "Set up email filtering rules to automatically detect and quarantine potential phishing emails or messages with suspicious attachments.",
        "icon": "📧"
    },
    {
        "level": "intermediate",
        "title": "Regular Data Backups",
        "content": "Follow the 3-2-1 backup rule: keep 3 copies of your data on 2 different media types with 1 copy stored offsite or in the cloud.",
        "icon": "💾"
    },
    {
        "level": "intermediate",
        "title": "Use Browser Security Extensions",
        "content": "Install security-focused browser extensions like ad blockers, script blockers, and tracker blockers to enhance your online privacy and security.",
        "icon": "🛡️"
    },
    {
        "level": "intermediate",
        "title": "Secure File Sharing",
        "content": "Use encrypted file sharing services with password protection and expiration dates when sharing sensitive documents with others.",
        "icon": "📁"
    },
    
    # Advanced Tips
    {
        "level": "advanced",
        "title": "Implement Network Segmentation",
        "content": "Separate your network into isolated segments to limit the spread of potential breaches. Keep IoT devices on a separate network from computers with sensitive data.",
        "icon": "🔌"
    },
    {
        "level": "advanced",
        "title": "Use Threat Intelligence Feeds",
        "content": "Subscribe to threat intelligence services to stay informed about emerging threats and vulnerabilities relevant to your systems and applications.",
        "icon": "📊"
    },
    {
        "level": "advanced",
        "title": "Deploy Intrusion Detection Systems",
        "content": "Implement IDS/IPS solutions to monitor network traffic for suspicious activities and automatically block potential threats in real-time.",
        "icon": "👁️"
    },
    {
        "level": "advanced",
        "title": "Conduct Regular Security Audits",
        "content": "Perform periodic security assessments including penetration testing, vulnerability scanning, and configuration reviews of your systems.",
        "icon": "📋"
    },
    {
        "level": "advanced",
        "title": "Implement DMARC for Email",
        "content": "Set up DMARC in conjunction with SPF and DKIM to protect your domain from email spoofing and improve email deliverability.",
        "icon": "✉️"
    },
    
    # Expert Tips
    {
        "level": "expert",
        "title": "Zero Trust Architecture",
        "content": "Adopt a 'never trust, always verify' approach by requiring strict identity verification for every person and device trying to access resources.",
        "icon": "🚫"
    },
    {
        "level": "expert",
        "title": "Security Orchestration and Automation",
        "content": "Implement SOAR platforms to automate security operations, incident response processes, and threat hunting activities.",
        "icon": "🤖"
    },
    {
        "level": "expert", 
        "title": "Secure Development Practices",
        "content": "Integrate security into the SDLC with practices like threat modeling, secure code reviews, and automated security testing in CI/CD pipelines.",
        "icon": "👨‍💻"
    },
    {
        "level": "expert",
        "title": "Hardware Security Modules",
        "content": "Use HSMs to manage and safeguard digital keys for strong authentication and provide cryptographic processing for critical security functions.",
        "icon": "🔒"
    },
    {
        "level": "expert",
        "title": "Security Information and Event Management",
        "content": "Deploy SIEM solutions to collect and analyze security events across your infrastructure for real-time threat detection and incident response.",
        "icon": "📡"
    }
]

# Function to get tips by level
def get_tips_by_level(level=None):
    """
    Get cybersecurity tips filtered by level.
    
    Args:
        level (str, optional): Filter tips by level (beginner, intermediate, advanced, expert)
        
    Returns:
        list: List of tips matching the requested level, or all tips if level is None
    """
    if level is None:
        return SECURITY_TIPS
    
    return [tip for tip in SECURITY_TIPS if tip["level"] == level]

# Function to get a random tip
def get_random_tip(level=None):
    """
    Get a random cybersecurity tip.
    
    Args:
        level (str, optional): Filter tips by level (beginner, intermediate, advanced, expert)
        
    Returns:
        dict: A random tip from the collection
    """
    import random
    tips = get_tips_by_level(level)
    if tips:
        return random.choice(tips)
    return None