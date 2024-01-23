const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
const nocache = require('nocache');
const path = require("path");
require('dotenv').config();

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const app = express();

app.use(express.json());
app.use(nocache());
app.use(cors());
app.use(express.static(path.join(__dirname, 'dist')));

app.post('/new', async (req, res) => {
    const { alias, lnurl, secret } = req.body;

    if (!alias || !lnurl || !secret) {
        return res.status(400).json({ "message": "Missing alias, lnurl, or password" });
    }
    if (alias.length > 20 || lnurl.length > 800 || secret.length > 128) {
        return res.status(400).json({ "message": "Input data exceeds maximum length" });
    }
    if (!alias.match(/^\w+$/)) {
        return res.status(400).json({ "message": "Alias can only contain letters, numbers, and underscores" });
    }

    const hash = bcrypt.hashSync(secret, bcrypt.genSaltSync(10));
    const { data, error } = await supabase
        .from('lnaddress')
        .insert([{ alias, lnurl, hash }]);

    if (error) {
        return res.status(400).json({ "message": "Error creating new entry" });
    }

    res.status(201).json({ "message": "Address created", "address": `${alias}@${req.get("host")}` });
});

app.get('/.well-known/lnurlp/:alias', async (req, res) => {
    const { alias } = req.params;
    const { data, error } = await supabase
        .from('lnaddress')
        .select("*")
        .eq("alias", alias);

    if (error || data.length === 0) {
        return res.status(404).json({ "message": "User not found" });
    }

    res.json(data[0]);
});

app.put('/update/:alias', async (req, res) => {
    const { alias } = req.params;
    const { secret, newAlias, newLnurl, newSecret } = req.body;

    const { data, error } = await supabase
        .from('lnaddress')
        .select("*")
        .eq("alias", alias);

    if (error || data.length === 0) {
        return res.status(404).json({ "message": "User not found" });
    }

    const user = data[0];
    if (bcrypt.compareSync(secret, user.hash)) {
        const newHash = newSecret ? bcrypt.hashSync(newSecret, bcrypt.genSaltSync(10)) : user.hash;
        const updatedAlias = newAlias || alias;
        const updatedLnurl = newLnurl || user.lnurl;

        const { error: updateError } = await supabase
            .from('lnaddress')
            .update({ alias: updatedAlias, lnurl: updatedLnurl, hash: newHash })
            .eq('id', user.id);  // Assuming 'id' is the primary key

        if (updateError) {
            return res.status(400).json({ "message": "Error updating data" });
        }

        res.status(200).json({ "message": "Update successful", "address": `${updatedAlias}@${req.get("host")}` });
    } else {
        res.status(401).json({ "message": "Unauthorized" });
    }
});

app.delete('/delete/:alias', async (req, res) => {
    const { alias } = req.params;
    const { secret } = req.body;

    const { data, error } = await supabase
        .from('lnaddress')
        .select("*")
        .eq("alias", alias);

    if (error || data.length === 0) {
        return res.status(404).json({ "message": "User not found" });
    }

    const user = data[0];
    if (bcrypt.compareSync(secret, user.hash)) {
        const { error: deleteError } = await supabase
            .from('lnaddress')
            .delete()
            .eq('id', user.id);  // Assuming 'id' is the primary key

        if (deleteError) {
            return res.status(400).json({ "message": "Error deleting data" });
        }

        res.status(200).json({ "message": "Deletion successful" });
    } else {
        res.status(401).json({ "message": "Unauthorized" });
    }
});

app.listen(3002, () => {
    console.log('Server listening on port 3002');
});
