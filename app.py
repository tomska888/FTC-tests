import sys, os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from gui.app import app

if __name__ == "__main__":
    app.run(debug=True)
