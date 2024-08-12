# research/app.py

from app import create_app  # Import the create_app function from the app package

# Create the app instance
app = create_app()

if _name_ == "_main_":
    # Run the Flask development server
    app.run(host='0.0.0.0', port=5000, debug=True)