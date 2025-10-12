---
-- Debian version mapping data file
-- Maps OpenSSH version + build to Debian release name
-- Source: https://github.com/richlamdev/ssh-default-banners

return {
  ["10.0p2-7"] = "Debian 13.x \"Trixie\" based",
  ["9.2p1-2"] = "Debian 12.x \"Bookworm\" based",
  ["8.4p1-5"] = "Debian 11.x \"Bullseye\" based",
  ["7.9p1-10"] = "Debian 10.x \"Buster\" based",
  ["7.4p-10"] = "Debian 9.x \"Stretch\" based",
  ["7.4p-9"] = "Debian 9.x \"Stretch\" based",
  ["6.7p1-5"] = "Debian 8.x \"Jessie\" based",
  ["6.0p1-4"] = "Debian 7.x \"Wheezy\" based",
  ["6.0p1-2"] = "Debian 7.x \"Wheezy\" based",
  ["5.8p1-4"] = "Debian 6.x \"Squeeze\" based",
  ["5.5p1-6"] = "Debian 6.x \"Squeeze\" based",
  ["5.1p1-5"] = "Debian 5.x \"Lenny\" based",
  ["4.3p2-9"] = "Debian 4.x \"Etch\" based",
  ["3.8.1p1-8"] = "Debian 3.1 \"Woody\" based",
  ["3.4p1-1"] = "Debian 3.0 \"Woody\" based"
}
