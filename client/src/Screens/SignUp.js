import { useState } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import classes from './SignUp.module.css';

const SignUpPage = ({ history }) => {
    const [displayName, setUsername] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [passwordCheck, setConfirmPassword] = useState("");
    const [error, setError] = useState("");

    const registerHandler = async (e) => {
        e.preventDefault();

        const config = {
            headers: {
                "Content-Type": "application/json",
            }
        };

        if (password !== passwordCheck) {
            setPassword("");
            setConfirmPassword("");
            setTimeout(() => {
                setError("");
            }, 5000);
            return setError("Passwords do not match");
        }

        try {
            await axios.post(
                "http://127.0.0.1:8000/api/users",
                {
                    email,
                    password,
                    passwordCheck,
                    displayName
                },
                config
            );

            //localStorage.setItem("authToken", data.token);

            //history.push("/");
        } catch (error) {
            console.log(error);
            // setError(error);
            // setTimeout(() => {
            //     setError("");
            // }, 5000);
        }
    };
    return (
        <div className={classes.register_screen}>
            <form onSubmit={registerHandler} className={classes.register_screen__form}>
                <h3 className={classes.register_screen__title}>Register</h3>
                {error && <span className="error-message">{error}</span>}
                <div className={classes.form_group}>
                    <label htmlFor="name">Username:</label>
                    <input
                        type="text"
                        required
                        id="name"
                        placeholder="Enter username"
                        value={displayName}
                        onChange={(e) => setUsername(e.target.value)}
                    />
                </div>
                <div className={classes.form_group}>
                    <label htmlFor="email">Email:</label>
                    <input
                        type="email"
                        required
                        id="email"
                        placeholder="Email address"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                    />
                </div>
                <div className={classes.form_group}>
                    <label htmlFor="password">Password:</label>
                    <input
                        type="password"
                        required
                        id="password"
                        autoComplete="true"
                        placeholder="Enter password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                    />
                </div>
                <div className={classes.form_group}>
                    <label htmlFor="confirmpassword">Confirm Password:</label>
                    <input
                        type="password"
                        required
                        id="confirmpassword"
                        autoComplete="true"
                        placeholder="Confirm password"
                        value={passwordCheck}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                    />
                </div>
                <button type="submit" className={classes.btn + classes.btn_primary}>
                    Register
                </button>

                <span className={classes.register_screen__subtext}>
                    Already have an account? <Link to="/login">Login</Link>
                </span>
            </form>
        </div>
    );
}
export default SignUpPage;