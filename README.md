# MandarinFish Router

Start the App
```
node app.js
```

Post Redirect Example
```
{
  "original": "Original IP",
  "redirect": "Redirect IP",
  "ports": [
    {
      "original": "80",
      "redirect": "3000"
    },
    {
      "original": "443",
      "redirect": "3001"
    }
  ]
}
```
