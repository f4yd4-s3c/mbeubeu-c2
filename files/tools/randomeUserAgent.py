import random
import sys

def generate_windows_os():
    return f"Windows NT {random.choice(['10.0', '6.3', '6.1'])}; Win64; x64"

def generate_mac_os():
    return "Macintosh; Intel Mac OS X %s" % random.choice([
        '10_15_7', '11_0_0', '12_0_0', '13_0', '14_0'
    ])

def generate_linux_os():
    return random.choice([
        'X11; Ubuntu; Linux x86_64',
        'X11; Fedora; Linux x86_64',
        'X11; Debian; Linux x86_64'
    ])

def generate_chrome_version():
    return f"{random.randint(90, 124)}.0.{random.randint(1000, 9999)}.{random.randint(0, 999)}"

def generate_firefox_version():
    return f"{random.randint(80, 126)}.0"

def generate_safari_version():
    major = random.randint(10, 17)
    minor = random.randint(0, 6)
    if random.random() < 0.3:
        return f"{major}.{minor}.{random.randint(0, 9)}"
    return f"{major}.{minor}"

def generate_edge_version():
    return f"{random.randint(90, 124)}.0.{random.randint(1000, 9999)}.{random.randint(0, 999)}"

def generate_random_user_agent():
    browsers = [
        # Chrome (50% probability)
        {
            'weight': 0.5,
            'generate': lambda: f"Mozilla/5.0 ({random.choice([generate_windows_os(), generate_mac_os(), generate_linux_os()])}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{generate_chrome_version()} Safari/537.36"
        },
        
        # Firefox (30% probability)
        {
            'weight': 0.3,
            'generate': lambda: (f"Mozilla/5.0 ({random.choice([generate_windows_os(), generate_mac_os(), generate_linux_os()])}; rv:{ver}) "
                             f"Gecko/20100101 Firefox/{ver}") if (ver := generate_firefox_version()) else ''
        },
        
        # Safari (15% probability)
        {
            'weight': 0.15,
            'generate': lambda: f"Mozilla/5.0 ({generate_mac_os()}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{generate_safari_version()} Safari/605.1.15"
        },
        
        # Edge (5% probability)
        {
            'weight': 0.05,
            'generate': lambda: f"Mozilla/5.0 ({random.choice([generate_windows_os(), generate_mac_os()])}) AppleWebKit/537.36 (KHTML, like Gecko) Edg/{generate_edge_version()}"
        }
    ]

    # Weighted random choice
    total = sum(b['weight'] for b in browsers)
    r = random.uniform(0, total)
    upto = 0
    for browser in browsers:
        if upto + browser['weight'] >= r:
            return browser['generate']()
        upto += browser['weight']
    return browsers[-1]['generate']()

# Example usage
if __name__ == '__main__':
    print(generate_random_user_agent())
