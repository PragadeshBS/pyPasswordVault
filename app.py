from flask import Flask, jsonify, render_template, request, redirect
import logic

app = Flask(__name__)

manager = logic.PasswordManager()


@app.route("/")
def index():
    if not manager.valid_master_pwd:
        return redirect("/get-master-password")
    return render_template("index.html")


@app.route("/add-password", methods=["GET", "POST"])
def store():
    if not manager.valid_master_pwd:
        return redirect("/get-master-password")
    if request.method == "POST":
        website = request.form["website"]
        username = request.form["username"]
        password = request.form["password"]
        manager.add_password(website, username, password)
        return render_template("add-password.html", message="Password stored!")
    return render_template("add-password.html")


@app.route("/get-master-password", methods=["GET", "POST"])
def get_master_password():
    if request.method == "POST":
        master_password = request.form["master-password"]
        manager.set_master_password(master_password)
        if not manager.valid_master_pwd:
            return render_template(
                "get-master-password.html", error="Invalid master password"
            )
        return redirect("/")
    return render_template("get-master-password.html")


@app.route("/get-password", methods=["GET", "POST"])
def retrieve():
    if not manager.valid_master_pwd:
        return redirect("/get-master-password")
    if request.method == "POST":
        website = request.form["website"]
        password = manager.get_password(website)
        if password:
            return render_template(
                "get-password.html", message=f"Password for {website}: {password}"
            )
        return render_template(
            "get-password.html",
            message="No password found for this website and username",
        )
    saved_passwords = manager.get_all_passwords()
    return render_template(
        "get-password.html",
        passwords=saved_passwords,
        websites=saved_passwords.keys(),
        passwords_count=len(saved_passwords),
    )


if __name__ == "__main__":
    app.run(debug=True)
