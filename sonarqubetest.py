# Deliberate Python issues for SonarQube testing

def compare_numbers(a, b):
    # Code Smell: Using obsolete "<>" operator for inequality (use "!=" instead)
    if a <> b:  # SonarQube will flag this as a code smell
        print("Numbers are not equal.")
    else:
        print("Numbers are equal.")

def process_data(data):
    # Bug: Using mutable default arguments, which can lead to unexpected behavior
    items = []
    for item in data:
        items.append(item)
    return items

class ExampleClass:
    static_var = "I'm static!"

    @staticmethod
    def show_static_var():
        # Code Smell: Accessing a static variable incorrectly
        print("$this: ", static_var)  # Simulating improper variable access

def html_header():
    # Bug: "<!DOCTYPE>" is missing before "<html>"
    html = """
    <html>
        <head>
            <title>Test Page</title>
        </head>
        <body>
            <p>Hello, world!</p>
        </body>
    </html>
    """
    return html

if __name__ == "__main__":
    compare_numbers(10, 20)  # Triggering the obsolete "<>" operator issue
    print(html_header())     # Generating user-experience bug for SonarQube testing