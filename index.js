const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const port = process.env.PORT || 5000;
const bcrypt = require("bcrypt");

const app = express();

// middleware
app.use(express.json());
// app.use(cookieParser());
//Must remove "/" from your production URL
app.use(
    cors({
        origin: ["http://localhost:5173", "https://quickcash-job-task.vercel.app"],
        credentials: true,
    }),
);

const uri = process.env.MONGODB_URI;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();
        // Send a ping to confirm a successful connection
        const db = client.db("QuickCashDB");
        const usersCollection = db.collection("users");

        // middleware
        const verifyToken = (req, res, next) => {
            // console.log("inside verify token", req.headers.authorization)
            if (!req.headers.authorization) {
                return res.status(401).send({ message: "unauthorized access" });
            }
            const token = req.headers.authorization.split(" ")[1];
            jwt.verify(token, process.env.TOKEN_SECRET, (err, decoded) => {
                if (err) {
                    return res.status(401).send({ message: "unauthorized access" });
                }
                req.decoded = decoded;
                next();
            });
        };

        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const user = await usersCollection.findOne({ email });
            if (user.role !== "admin") {
                return res.status(403).send({ message: "Forbidden access!" });
            }
            next();
        };

        app.get("/userInfo", verifyToken, async (req, res) => {
            user = req.decoded;
            // console.log(user);
            const result = await usersCollection.findOne({ email: req.decoded.email });
            res.send(result);
        });

        app.post("/jwt", (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.TOKEN_SECRET, { expiresIn: "365d" });
            res.send({ token });
        });

        // app.post("/logout", (req, res) => {
        //     res.clearCookie("token", { ...cookieOptions, maxAge: 0 }).send({ success: true });
        // });

        app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
            const search = req.query.search;
            let query = {};
            // let query = { $or: [{ role: "user" }, { role: "agent" }] };
            // if (search) {
            //     query = { $and: [{ $or: [{ role: "user" }, { role: "agent" }] }, { name: { $regex: search, $options: "i" } }] };
            // }
            if (search) {
                query = { name: { $regex: search, $options: "i" } };
            }
            const result = await usersCollection.find(query).toArray();
            res.send(result);
        });

        app.patch("/userStatus/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const role = req.body.role;
            const status = req.body.status;
            const button = req.body.button;
            // console.log(id, role, status, button);
            let updateDoc = {
                $set: {
                    status: button,
                },
            };
            if (button === "approved" && status === "pending") {
                if (role === "user") {
                    updateDoc = {
                        $set: {
                            status: "approved",
                            balance: 40,
                        },
                    };
                }
                if (role === "agent") {
                    updateDoc = {
                        $set: {
                            status: "approved",
                            balance: 10000,
                        },
                    };
                }
            }
            const result = await usersCollection.updateOne({ _id: new ObjectId(id) }, updateDoc);
            res.send(result);
        });

        app.post("/login/:email", async (req, res) => {
            const email = req.params.email;
            const pin = req.body.pin;
            const user = await usersCollection.findOne({ email });
            const pinMatching = bcrypt.compareSync(pin, user.pin);
            if (!pinMatching || !user) {
                return res.send({ message: "Invalid credentials!", status: 403 });
            }
            res.send(user);
        });

        app.post("/createUser", async (req, res) => {
            const user = req.body;
            const hashPin = bcrypt.hashSync(user.pin, 10);
            const isExist = await usersCollection.findOne({ email: user.email });
            if (isExist) {
                return res.send({ message: "user already exist!", status: isExist.status });
            }
            const doc = {
                ...user,
                pin: hashPin,
            };
            const result = await usersCollection.insertOne(doc);
            res.send(result);
        });

        app.get("/role/:email", verifyToken, async (req, res) => {
            const email = req.params.email;
            const user = await usersCollection.findOne({ email: email });
            const role = user.role;
            res.send({ role });
        });

        // await client.db("admin").command({ ping: 1 });
        // console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);

app.get("/", (req, res) => {
    res.send("QuickCash is running...");
});

app.listen(port, () => {
    console.log("QuickCash server running on", port);
});
