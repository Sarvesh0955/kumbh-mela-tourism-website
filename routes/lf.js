const express = require('express');
const router = express.Router();
const {validate,upload} = require('../middleware');
require('dotenv').config();
const {Item, Item2} = require('../models/item');

//lost and found
router.get('/adminsolve', (req, res) => {
    res.render('./lf/adminsolve');
})

router.get('/main', (req, res) => {
    res.render('./lf/main');
})

router.get('/landf', (req, res) => {
    res.render('./lf/lost-found');
})

router.get('/form', (req, res) => {
    res.render('./lf/index');
})

router.post('/items', upload.single('photo'), async (req, res) => {
    try {
        const newItem = new Item({
            landf: req.body.landf,
            title: req.body.title,
            type: req.body.type,
            description: req.body.description,
            location: req.body.location,
            date: req.body.date,
            phone: req.body.phone,
            photo: req.file ? `/uploads/${req.file.filename}` : null
        });
        await newItem.save();
        res.status(201).json(newItem);
    } catch (error) {
        console.error('Error saving item:', error);
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
});

router.get('/type/:id', async (req, res) => {
    try {
        const type = req.params.id;
        const itemsOfType = await Item.find({ type: { $regex: new RegExp(type, 'i') } });
        res.render('./lf/type', { type, items: itemsOfType });
    } catch (error) {
        console.error('Error retrieving items by type:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

router.get('/location/:location', async (req, res) => {
    const location = req.params.location;
    const type = req.query.type;
    const landf = req.query.landf;
    const query = {
        location: { $regex: new RegExp(location, "i") }
    };
    if (type && type !== "all") {
        query.type = type;
    }
    if (landf && landf !== "all") {
        query.landf = landf;
    }
    try {
        const items = await Item.find(query);
        res.render('./lf/location', { items, location, type, landf });
    } catch (error) {
        console.error('Error fetching items:', error);
        res.status(500).send('Internal Server Error');
    }
});

router.post('/claim-item', async (req, res) => {
    try {
        const newClaimedItem = new Item2({
            id: req.body.userid,
            description: req.body.description,
            phone: req.body.phone
        });
        await newClaimedItem.save();
        res.status(201).json(newClaimedItem);
    } catch (error) {
        console.error('Error saving claimed item:', error);
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
});

router.get('/claim-item', async (req, res) => {
    try {
        const items = await Item2.find();
        console.log(items)
        res.json(items);
    } catch (error) {
        console.error('Error retrieving items:', error);
        res.status(500).json({ message: 'Server Error' });
    }
})

router.get('/admin-claim-requests', async (req, res) => {
    try {
        const claims = await Item2.find();
        const itemsWithClaims = [];
        for (let claim of claims) {
            const foundItem = await Item.findById(claim.id);
            if (foundItem) {
                itemsWithClaims.push({
                    foundItem: foundItem,
                    claim: claim
                });
            }
        }
        res.json(itemsWithClaims);
    } catch (error) {
        console.error('Error retrieving claim requests with items:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

router.delete('/claim-item/:id', async (req, res) => {
    try {
        const claimId = req.params.id;
        const deletedClaim = await Item2.findByIdAndDelete(claimId);
        if (!deletedClaim) {
            return res.status(404).json({ message: 'Claim not found' });
        }
        res.status(200).json({ message: 'Claim deleted successfully' });
    } catch (error) {
        console.error('Error deleting claim:', error);
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
});

router.get('/items', async (req, res) => {
    try {
        const items = await Item.find();
        res.json(items);
    } catch (error) {
        console.error('Error retrieving items:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

router.get('/items/:id', async (req, res) => {
    try {
        const item = await Item.findById(req.params.id);
        if (!item) return res.status(404).json({ message: 'Item not found' });
        res.render('./lf/itemDetail', { item });
    } catch (error) {
        console.error('Error retrieving item by ID:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

router.get('/location/:id', async (req, res) => {
    try {
        const location = req.params.id.toLowerCase();
        const itemType = req.query.type;
        let query = { location: { $regex: new RegExp(location, 'i') } };
        if (itemType) {
            query.type = itemType;
            const itemsAtLocation = await Item.find(query);
        }
        res.render('./lf/location', { location, items: itemsAtLocation });
    } catch (error) {
        console.error('Error retrieving items by location:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

router.get('/itemlist', (req, res) => {
    res.render('./lf/itemlist');
});

router.delete('/found-item/:id', async (req, res) => {
    try {
        const itemId = req.params.id;
        const deletedItem = await Item.findByIdAndDelete(itemId);
        if (!deletedItem) {
            return res.status(404).json({ message: 'Item not found' });
        }
        await Item2.deleteMany({ id: itemId });
        res.status(200).json({ message: 'Item and associated claims deleted successfully' });
    } catch (error) {
        console.error('Error deleting item and claims:', error);
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
});

module.exports = router;