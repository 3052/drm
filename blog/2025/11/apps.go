package playReady

type app struct {
   url   string
   title string
   rank  string
   drm   string
}

var Details = map[string][]app{
   "100M+ Downloads": {
      {
         url:   "play.google.com/store/apps/details?id=com.tubitv",
         title: "Tubi: Free Movies & Live TV",
         rank:  "#4 top free entertainment",
         drm:   "clearKey",
      },
      {
         url:   "play.google.com/store/apps/details?id=tv.pluto.android",
         title: "PlutoTV: Live TV & Free Movies",
         rank:  "#9 top free entertainment",
         drm:   "there is an error with this content",
      },
      {
         url:   "play.google.com/store/apps/details?id=com.wbd.stream",
         title: "Max: Stream HBO, TV, & Movies",
         rank:  "#1 top grossing entertainment",
      },
   },
   "50M+ Downloads": {
      {
         drm:   "there was an error loading the video",
         title: "Plex: Stream Movies & TV",
         url:   "play.google.com/store/apps/details?id=com.plexapp.android",
      },
      {
         drm:   "sign up now",
         title: "Hulu: Stream TV shows & movies",
         url:   "play.google.com/store/apps/details?id=com.hulu.plus",
      },
   },
   "10M+ Downloads": {
      {
         drm:   "login",
         title: "The NBC App - Stream TV Shows",
         url:   "play.google.com/store/apps/details?id=com.nbcuni.nbc",
      },
      {
         drm:   "sign in",
         title: "Paramount+",
         url:   "play.google.com/store/apps/details?id=com.cbs.app",
      },
      {
         title: "ITVX",
         url:   "play.google.com/store/apps/details?id=air.ITVMobilePlayer",
         drm:   "sign in",
      },
      /////////////////////////////////////////////////////////////////////////////////
      {
         title: "CANAL+, Live and catch-up TV",
         url:   "play.google.com/store/apps/details?id=com.canal.android.canal",
         drm:   "register",
      },
      {
         title: "Molotov - TV en direct, replay",
         url:   "play.google.com/store/apps/details?id=tv.molotov.app",
         drm:   "available in a fee-paying option",
      },
      {
         title: "Movistar Plus+",
         url:   "play.google.com/store/apps/details?id=es.plus.yomvi",
         drm:   "log in",
      },
   },
   "5M+ Downloads": {
      {
         drm:   "log in",
         title: "MUBI: Curated Cinema",
         url:   "play.google.com/store/apps/details?id=com.mubi",
      },
      {
         drm:   "web client need residential proxy, license does not",
         title: "Rakuten TV -Movies & TV Series",
         url:   "play.google.com/store/apps/details?id=tv.wuaki",
      },
   },
   "1M+ Downloads": {
      {
         drm:   "to see this content, log in",
         title: "RTBF Auvio : direct et replay",
         url:   "play.google.com/store/apps/details?id=be.rtbf.auvio",
      },
      {
         drm:   "sign up now",
         title: "AMC+",
         url:   "play.google.com/store/apps/details?id=com.amcplus.amcfullepisodes",
      },
      {
         drm:   "log in",
         title: "Kanopy",
         url:   "play.google.com/store/apps/details?id=com.kanopy",
      },
      {
         drm:   "failed to load response data",
         title: "The Roku Channel",
         url:   "play.google.com/store/apps/details?id=com.roku.web.trc",
      },
      {
         drm: `they keep two copies of all content, so PR key is different
         from WV key`,
         title: "CTV",
         url:   "play.google.com/store/apps/details?id=ca.ctv.ctvgo",
      },
   },
   "100K+ Downloads": {
      {
         drm:   "subscribe",
         title: "The Criterion Channel",
         url:   "play.google.com/store/apps/details?id=com.criterionchannel",
      },
   },
   "10K+ Downloads": {
      {
         drm:   "log in",
         title: "CineMember",
         url:   "play.google.com/store/apps/details?id=nl.peoplesplayground.audienceplayer.cinemember",
      },
      {
         drm:   "join",
         title: "Draken Film",
         url:   "play.google.com/store/apps/details?id=com.draken.android",
      },
   },
}
