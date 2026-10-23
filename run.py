from app import create_app

app = create_app()

if __name__ == '__main__':
    # Security: Host ko localhost (127.0.0.1) par bind kiya hai
    app.run(host='127.0.0.1', port=5000, debug=True)