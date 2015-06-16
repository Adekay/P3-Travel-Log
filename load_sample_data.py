from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Region, Base, Place, User
import httplib2
import json
import datetime
import time

engine = create_engine('sqlite:///travelbucketlist.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

print "Generating users..."

# Create dummy user
def GenerateUser(visible):

    # Need to wait between requests in order for the random user api to select different users   
    time.sleep(2)

    # Retrieve random user info for dummy user accounts
    url = 'http://api.randomuser.me/'
    h = httplib2.Http()

    # Create dummy user
    result = h.request(url, 'GET')[1]
    res = json.loads(result)
    data = res["results"][0]["user"]

    return User(name="%s, %s" % (data["name"]["first"], data["name"]["last"]), 
                email=data["email"],
                picture=data["picture"]["medium"],
                allow_public_access=visible,
                signup_date=datetime.datetime.fromtimestamp(float(data["registered"]))
                )

# Create dummy user 1
user1 = GenerateUser(1)
session.add(user1)

# Create dummy user 2
user2 = GenerateUser(1)
session.add(user2)

# Create dummy user 3
user3 = GenerateUser(1)
session.add(user3)

# Create dummy user 4
user4 = GenerateUser(1)
session.add(user4)



print "Generating regions..."

region11 = Region(name = "Japan",
    picture = "tb000004.jpg",
    geo_location = "https://www.google.ca/maps/place/Japan/@34.7857324,134.3756902,5z/data=!3m1!4b1!4m2!3m1!1s0x34674e0fd77f192f:0xf54275d47c665244",
    rating = 8,
    creation_date = datetime.datetime(2014, 03, 15, 9, 23, 03),
    modifiy_date = datetime.datetime(2014, 03, 15, 9, 23, 03),
    user = user1
)
session.add(region11)

region12 = Region(name = "New Zealand",
    picture = "tb000009.jpg",
    geo_location = "https://www.google.ca/maps/place/New+Zealand/data=!4m2!3m1!1s0x6d2c200e17779687:0xb1d618e2756a4733?sa=X&ei=AM50Vev3FsH-yQSThIKABw&ved=0CIIBEPIBMBI",
    rating = 9,
    creation_date = datetime.datetime(2013, 8, 15, 15, 45, 22),
    modifiy_date = datetime.datetime(2013, 8, 15, 15, 45, 22),
    user = user1
)
session.add(region12)

region13 = Region(name = "Montreal",
    picture = "tb000007.jpg",
    geo_location = "https://www.google.ca/maps/place/Montreal,+QC/data=!4m2!3m1!1s0x4cc91a541c64b70d:0x654e3138211fefef?sa=X&ei=Z850VfOUBsivyATM1rWQDA&ved=0CIYBEPIBMBI",
    rating = 8,
    creation_date = datetime.datetime(2015, 01, 22, 11, 9, 22),
    modifiy_date = datetime.datetime(2015, 01, 22, 11, 9, 22),
    user = user1
)
session.add(region13)


region21 = Region(name = "New Zealand",
    picture = "tb000010.jpg",
    geo_location = "https://www.google.ca/maps/place/New+Zealand/data=!4m2!3m1!1s0x6d2c200e17779687:0xb1d618e2756a4733?sa=X&ei=AM50Vev3FsH-yQSThIKABw&ved=0CIIBEPIBMBI",
    rating = 8,
    creation_date = datetime.datetime(2014, 05, 04, 7, 55, 47),
    modifiy_date = datetime.datetime(2014, 05, 04, 7, 55, 47),
    user = user2
)
session.add(region21)

region22 = Region(name = "Australia",
    picture = "tb000001.jpg",
    geo_location = "https://www.google.ca/maps/place/Australia/data=!4m2!3m1!1s0x2b2bfd076787c5df:0x538267a1955b1352?sa=X&ei=CdB0VYuoLY73yQSC-IOYBg&ved=0CIIBEPIBMBI",
    rating = 7,
    creation_date = datetime.datetime(2014, 05, 04, 7, 58, 24),
    modifiy_date = datetime.datetime(2014, 05, 04, 7, 58, 24),
    user = user2
)
session.add(region22)


region31 = Region(name = "New York City",
    picture = "tb000005.jpg",
    geo_location = "https://www.google.ca/maps/place/New+York,+NY,+USA/@40.7033127,-73.979681,10z/data=!3m1!4b1!4m2!3m1!1s0x89c24fa5d33f083b:0xc80b8f06e177fe62",
    rating = 9,
    creation_date = datetime.datetime(2014, 12, 23, 7, 42, 17),
    modifiy_date = datetime.datetime(2014, 12, 23, 7, 42, 17),
    user = user3
)
session.add(region31)

region32 = Region(name = "Nepal",
    picture = "tb000006.jpg",
    geo_location = "https://www.google.ca/maps/place/Nepal/data=!4m2!3m1!1s0x3995e8c77d2e68cf:0x34a29abcd0cc86de?sa=X&ei=sNB0VaOmLpKayATnmoOACg&ved=0CIMBEPIBMBI",
    rating = 10,
    creation_date = datetime.datetime(2012, 6, 15, 14, 33, 38),
    modifiy_date = datetime.datetime(2012, 6, 15, 14, 33, 38),
    user = user3
)
session.add(region32)


region41 = Region(name = "New York City",
    picture = "tb000011.jpg",
    geo_location = "https://www.google.ca/maps/place/New+York,+NY,+USA/@40.7033127,-73.979681,10z/data=!3m1!4b1!4m2!3m1!1s0x89c24fa5d33f083b:0xc80b8f06e177fe62",
    rating = 9,
    creation_date = datetime.datetime(2014, 12, 14, 12, 34, 17),
    modifiy_date = datetime.datetime(2014, 12, 14, 12, 34, 17),
    user = user4
)
session.add(region41)

region42 = Region(name = "Detroit",
    picture = "tb000002.jpg",
    geo_location = "https://www.google.ca/maps/place/Detroit,+MI,+USA/@42.352711,-83.099205,11z/data=!3m1!4b1!4m2!3m1!1s0x8824ca0110cb1d75:0x5776864e35b9c4d2",
    rating = 5,
    creation_date = datetime.datetime(2014, 12, 14, 12, 34, 17),
    modifiy_date = datetime.datetime(2014, 12, 14, 12, 34, 17),
    user = user4
)
session.add(region42)

region43 = Region(name = "San Francisco",
    picture = "tb000008.jpg",
    geo_location = "https://www.google.ca/maps/place/San+Francisco,+CA,+USA/data=!4m2!3m1!1s0x80859a6d00690021:0x4a501367f076adff?sa=X&ei=k9F0VeyjCov3yQSp7YGADw&ved=0CJcBEPIBMBI",
    rating = 9,
    creation_date = datetime.datetime(2014, 12, 14, 12, 34, 17),
    modifiy_date = datetime.datetime(2014, 12, 14, 12, 34, 17),
    user = user4
)
session.add(region43)

region44 = Region(name = "Germany",
    picture = "tb000003.jpg",
    geo_location = "https://www.google.ca/maps/place/Germany/data=!4m2!3m1!1s0x479a721ec2b1be6b:0x75e85d6b8e91e55b?sa=X&ved=0CIcBEPIBMBNqFQoTCM_9jMOEjcYCFYoVkgodeaoAtA",
    rating = 9,
    creation_date = datetime.datetime(2015, 6, 14, 9, 34, 17),
    modifiy_date = datetime.datetime(2015, 6, 14, 9, 34, 17),
    user = user4
)
session.add(region44)



print "Generating places..."

place111 = Place(name = "Visit Tokyo",
    description = "Tokyo, Japan's bustling capital, mixes the ultramodern and the traditional, from neon-lit skyscrapers and anime shops to cherry trees and temples. The opulent Meiji Shinto Shrine is known for its towering gate and surrounding forests. The Imperial Palace sits amid sprawling public gardens. The city is famed for its vibrant food scene, and its Shibuya and Harajuku districts are the heart of its trendy teen fashion scene.",
    picture = "http://www.businessdestinations.com/wp-content/uploads/2013/12/Tokyo-Main-Image-800x600.jpg",
    geo_location = "https://www.google.ca/maps/place/Tokyo,+Japan/data=!4m2!3m1!1s0x605d1b87f02e57e7:0x2e01618b22571b89?sa=X&ei=09Z0VaDWE8-WyASgporwCw&ved=0CJcBEPIBMBI",
    info_website = "http://www.gotokyo.org/en/",
    rating = 7,
    creation_date = region11.creation_date,
    modifiy_date = region11.creation_date,
    region = region11,
    user = user1
    )
session.add(place111)

place112 = Place(name = "Climb Mount Fuji",
    description = "Mount Fuji, located on Honshu Island, is the highest mountain in Japan at 3,776.24 m. An active stratovolcano that last erupted in 1707-08, Mount Fuji lies about 100 kilometres south-west of Tokyo, and can be seen from there on a clear day.",
    picture = "http://wikitravel.org/upload/shared//thumb/d/d5/FujiSunriseKawaguchiko2025WP.jpg/400px-FujiSunriseKawaguchiko2025WP.jpg",
    geo_location = "https://www.google.ca/maps/place/Mt+Fuji/data=!4m2!3m1!1s0x60196290556df7cf:0x8d5003885b877511!5m1!1e4?sa=X&ei=PNd0VaeaJZGSyAS7zIKwDg&ved=0CJIBEPIBMA4",
    info_website = "http://www.japan-guide.com/e/e2172.html",
    rating = 9,
    creation_date = region11.creation_date,
    modifiy_date = region11.creation_date,
    region = region11,
    user = user1
    )
session.add(place112)


place121 = Place(name = "Go to Queenstown",
    description = "Queenstown, New Zealand, sits on the shore of the South Island's Lake Wakatipu, set against the dramatic Southern Alps. The surrounding Central Otago region is known for its Pinot Noir and Chardonnay vineyards, and for adventure sports. In winter, there's backcountry skiing and the country's highest vertical drops. Summer brings paragliding, mountain biking and bungee-jumping (Kawarau Gorge Suspension Bridge is among the sport's original sites).",
    picture = "http://upload.wikimedia.org/wikipedia/commons/e/e2/Queenstown_from_Bob's_Peak.jpg",
    geo_location = "https://www.google.ca/maps/place/Queenstown,+New+Zealand/data=!4m2!3m1!1s0xa9d51df1d7a8de5f:0x500ef868479a600?sa=X&ei=s9d0VcKlK86YyATh34PwAQ&ved=0CJkBEPIBMBA",
    info_website = "http://www.japan-guide.com/e/e2172.html",
    rating = 9,
    creation_date = region12.creation_date,
    modifiy_date = region12.creation_date,
    region = region12,
    user = user1
    )
session.add(place121)

place122 = Place(name = "Milford Sound",
    description = "Milford Sound is a fiord in the south west of New Zealand's South Island, within Fiordland National Park, Piopiotahi Marine Reserve, and the Te Wahipounamu World Heritage site.",
    picture = "http://farm1.nzstatic.com/_proxy/imageproxy_1y/serve/milford-sound-timelapse.webp?height=440&outputformat=webp&quality=80&source=http://c0481729.cdn2.cloudfiles.rackspacecloud.com/p-7D0FBBFB-9EEE-7FE3-DB301E4FED24A0E5-3752696.png&transformationsystem=crop&width=1280&securitytoken=50CEEFB5A95B8277F7CB2B12F6700C62",
    geo_location = "https://www.google.ca/maps/place/Milford+Sound/data=!4m2!3m1!1s0xa9d5e04dba4b49e1:0x2a00ef86ab64de00?sa=X&ei=E9h0VYWHM8X9yQS1rIDIAw&ved=0CIUBEPIBMA4",
    info_website = "http://www.milford-sound.co.nz/",
    rating = 9,
    creation_date = region12.creation_date,
    modifiy_date = region12.creation_date,
    region = region12,
    user = user1
    )
session.add(place122)



place211 = Place(name = "Go to Queenstown",
    description = "Queenstown, New Zealand, sits on the shore of the South Island's Lake Wakatipu, set against the dramatic Southern Alps. The surrounding Central Otago region is known for its Pinot Noir and Chardonnay vineyards, and for adventure sports. In winter, there's backcountry skiing and the country's highest vertical drops. Summer brings paragliding, mountain biking and bungee-jumping (Kawarau Gorge Suspension Bridge is among the sport's original sites).",
    picture = "http://upload.wikimedia.org/wikipedia/commons/e/e2/Queenstown_from_Bob's_Peak.jpg",
    geo_location = "https://www.google.ca/maps/place/Queenstown,+New+Zealand/data=!4m2!3m1!1s0xa9d51df1d7a8de5f:0x500ef868479a600?sa=X&ei=s9d0VcKlK86YyATh34PwAQ&ved=0CJkBEPIBMBA",
    info_website = "http://www.japan-guide.com/e/e2172.html",
    rating = 8,
    creation_date = region21.creation_date,
    modifiy_date = region21.creation_date,
    region = region21,
    user = user1
    )
session.add(place211)

place212 = Place(name = "Milford Sound",
    description = "Milford Sound is a fiord in the south west of New Zealand's South Island, within Fiordland National Park, Piopiotahi Marine Reserve, and the Te Wahipounamu World Heritage site.",
    picture = "http://farm1.nzstatic.com/_proxy/imageproxy_1y/serve/milford-sound-timelapse.webp?height=440&outputformat=webp&quality=80&source=http://c0481729.cdn2.cloudfiles.rackspacecloud.com/p-7D0FBBFB-9EEE-7FE3-DB301E4FED24A0E5-3752696.png&transformationsystem=crop&width=1280&securitytoken=50CEEFB5A95B8277F7CB2B12F6700C62",
    geo_location = "https://www.google.ca/maps/place/Milford+Sound/data=!4m2!3m1!1s0xa9d5e04dba4b49e1:0x2a00ef86ab64de00?sa=X&ei=E9h0VYWHM8X9yQS1rIDIAw&ved=0CIUBEPIBMA4",
    info_website = "http://www.milford-sound.co.nz/",
    rating = 10,
    creation_date = region21.creation_date,
    modifiy_date = region21.creation_date,
    region = region21,
    user = user1
    )
session.add(place212)

place212 = Place(name = "Abel Tasman",
    description = "Abel Tasman National Park is a New Zealand national park located between Golden Bay and Tasman Bay at the north end of the South Island.",
    picture = "http://farm1.nzstatic.com/_proxy/imageproxy_1y/serve/peaceful-awaroa-inlet-in-abel-tasman-national-park.webp?height=530&outputformat=webp&quality=80&source=964207&transformationratio=1.3&transformationsystem=autoboxfit&width=940&securitytoken=75D86E3FB92861625A9BFFB8D40F2702",
    geo_location = "https://www.google.ca/maps/place/abel+tasman+national+park/@-40.934685,172.972155,10z/data=!4m2!3m1!1s0x0:0xf00ef87655bee50?sa=X&ei=Zdl0VY3YIZCZyATp1YCgCA&ved=0CJQBEPwSMBA",
    info_website = "https://www.abeltasman.co.nz/",
    rating = 9,
    creation_date = region21.creation_date,
    modifiy_date = region21.creation_date,
    region = region21,
    user = user1
    )
session.add(place212)


session.commit()

print "Sample Data Generation Complete."
