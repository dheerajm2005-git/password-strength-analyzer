from flask import Flask, render_template, request

from analyzer import analyze_password
from generator import generate_password

from database import (
    create_database,
    save_password,
    is_password_reused
)


app = Flask(__name__)

create_database()


@app.route("/", methods=["GET", "POST"])
def home():

    password = ""
    result = None
    generated_password = None
    reuse_message = None

    if request.method == "POST":

        action = request.form.get("action")

        # -------------------------
        # ANALYZE PASSWORD
        # -------------------------

        if action == "analyze":

            password = request.form.get("password", "")

            reused = is_password_reused(password)

            score, strength, suggestions, entropy = analyze_password(password)

            result = {
                "strength": strength,
                "score": score,
                "suggestions": suggestions,
                "entropy": entropy,
                "reused": reused
            }


        # -------------------------
        # GENERATE PASSWORD
        # -------------------------

        elif action == "generate":

            generated_password = generate_password(16)


        # -------------------------
        # SAVE PASSWORD
        # -------------------------

        elif action == "save":

            password = request.form.get("password", "")

            if password:

                if is_password_reused(password):

                    reuse_message = (
                        "⚠ This password has already been used."
                    )

                else:

                    save_password(password)

                    reuse_message = (
                        "✓ Password securely added to password history."
                    )


    return render_template(
        "index.html",
        password=password,
        result=result,
        generated_password=generated_password,
        reuse_message=reuse_message
    )


if __name__ == "__main__":
    app.run(debug=True)